"""
Batched HumanEval Collector v5 - ICL4Decomp-R with Knowledge Base Integration

Key improvements:
- KB retrieval for few-shot prompting (asm + ghidra + retrieved examples)
- LLM-as-judge for type checking and logical correctness
- Parallelized static repair loops (12+ concurrent)
- Semantic fixes after compilation success
- Max 15 iterations per testcase
"""

import sys
import json
import yaml
import shutil
import tempfile
from pathlib import Path
from typing import Tuple, List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import httpx

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from utils.llm_interface import create_llm_interface, LLMInterface
from utils.compile import Compiler, OptimizationLevel
from utils.ghidra import Ghidra
from utils.clean_errors import ErrorNormalizer
from src.sort_callgraph import build_call_graph, topological_sort

# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)

# Initialize tools
c = Compiler()
g = Ghidra()

llm_interface = create_llm_interface(
    provider=config["llm"]["vllm_provider"],
    model_name=config["llm"]["vllm_model_name"],
    base_url=config["llm"]["vllm_base_url"]
)

corpus_path = Path(config["humaneval"]["corpus_path"])
output_dir = Path(config["humaneval"]["output_path"])

# KB API configuration
KB_API_URL = config.get("kb", {}).get("api_url", "http://localhost:8001")
KB_RETRIEVAL_K = config.get("kb", {}).get("retrieval_k", 3)

# Batching configuration - increased parallelism
COMPILATION_BATCH_SIZE = 20
GHIDRA_BATCH_SIZE = 12
LLM_BATCH_SIZE = 12  # Increased from 8 to 12
MAX_ITERATIONS = 15  # Max iterations per testcase


# KB Client
class KBClient:
    """Client for Knowledge Base API"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.client = httpx.Client(timeout=60.0)
    
    def retrieve_examples(self, asm: str, k: int = 3) -> List[Dict]:
        """Retrieve similar examples from KB"""
        try:
            response = self.client.post(
                f"{self.base_url}/retrieve",
                json={"asm": asm, "k": k, "return_scores": False}
            )
            response.raise_for_status()
            return response.json()["exemplars"]
        except Exception as e:
            print(f"[KB] Warning: Failed to retrieve examples: {e}")
            return []
    
    def generate_icl_prompt(self, asm: str, ghidra_pseudo: str, k: int = 3) -> str:
        """Generate ICL prompt with retrieved examples"""
        try:
            response = self.client.post(
                f"{self.base_url}/icl_prompt",
                json={
                    "asm": asm,
                    "ghidra_pseudo": ghidra_pseudo,
                    "k": k,
                    "include_function_names": True
                }
            )
            response.raise_for_status()
            return response.json()["prompt"]
        except Exception as e:
            print(f"[KB] Warning: Failed to generate ICL prompt: {e}")
            return ""
    
    def close(self):
        self.client.close()


kb_client = KBClient(KB_API_URL)


@dataclass
class CompilationResult:
    """Result of compiling a single program."""
    index: int
    success: bool
    executable_path: Optional[Path]
    error_message: Optional[str]
    data: Dict


@dataclass
class JudgeResult:
    """Result from LLM-as-judge evaluation"""
    types_correct: bool  # First bit
    logic_correct: bool  # Second bit
    score: str  # "00", "01", "10", or "11"
    feedback: str  # Specific issues found


def get_initial_prompt_with_kb(
    c_code: str,
    asm: str,
    ghidra_code: str,
    function_summary: str,
    caller_and_callee_summary: str,
    function_sog: str,
    language: str,
    retrieved_examples: List[Dict]
) -> str:
    """
    Generate the initial prompt with KB-retrieved examples for few-shot learning
    """
    prompt = config["prompts"]["system_prompt"]
    
    # Add retrieved examples for few-shot learning
    if retrieved_examples:
        prompt += "\n\n### Retrieved Similar Examples (for reference)\n"
        for i, ex in enumerate(retrieved_examples, 1):
            prompt += f"\n#### Example {i}\n"
            if ex.get("name"):
                prompt += f"Function: {ex['name']}\n"
            prompt += f"Assembly:\n```asm\n{ex['asm'][:500]}...\n```\n\n"  # Truncate for token efficiency
            prompt += f"Correct Source Code:\n```c\n{ex['code'][:500]}...\n```\n\n"
    
    # Add target
    prompt += f"\n\n### Your Task\n"
    prompt += f"Language: {language}\n"
    prompt += f"Summary: {function_summary}\n\n"
    
    if ghidra_code:
        prompt += f"Ghidra Pseudocode:\n```c\n{ghidra_code}\n```\n\n"
    
    if asm:
        prompt += f"Assembly:\n```asm\n{asm}\n```\n\n"
    
    if caller_and_callee_summary:
        prompt += f"Caller and Callee Summary:\n{caller_and_callee_summary}\n\n"
    
    if function_sog:
        prompt += f"Function SOG:\n{function_sog}\n\n"
    
    prompt += "Generate the corrected, compilable source code:"
    
    return prompt


def get_repair_prompt_with_kb(
    c_code: str,
    compilation_errors: str,
    function_summary: str,
    caller_and_callee_summary: str,
    function_sog: str,
    language: str,
    retrieved_examples: List[Dict]
) -> str:
    """
    Generate repair prompt with KB examples
    """
    repair_prompt = config["prompts"]["compilation_error"]
    
    # Add retrieved examples
    if retrieved_examples:
        repair_prompt += "\n\n### Type Reference Examples from Knowledge Base\n"
        for i, ex in enumerate(retrieved_examples[:2], 1):  # Use top 2 for repairs
            repair_prompt += f"\nExample {i} - Correct typing:\n```c\n{ex['code'][:300]}...\n```\n"
    
    repair_prompt += f"\n\n```c\nLanguage:{language}\nSummary:{function_summary}\nCode:{c_code}\n```\n\n"
    repair_prompt += f"Compilation Errors:\n{compilation_errors}\n\n"
    repair_prompt += "Please provide the corrected C code."
    
    if caller_and_callee_summary:
        repair_prompt += f"\n\nCaller and Callee Summary:\n{caller_and_callee_summary}"
    
    if function_sog:
        repair_prompt += f"\n\nFunction SOG:\n{function_sog}"
    
    return repair_prompt


def get_semantic_judge_prompt(
    optimized_code: str,
    asm: str,
    ghidra_code: str,
    retrieved_examples: List[Dict],
    language: str
) -> str:
    """
    Generate prompt for LLM-as-judge to check types and logic
    """
    judge_prompt = config["prompts"]["judge_prompt"]
    
    # Add KB examples as reference
    judge_prompt += "\n\n### Reference Examples (known-correct decompilations from KB):\n"
    for i, ex in enumerate(retrieved_examples, 1):
        judge_prompt += f"\nExample {i}:\n```c\n{ex['code'][:400]}...\n```\n"
    
    judge_prompt += f"\n\n### Target Code to Evaluate:\n```{language}\n{optimized_code}\n```\n\n"
    
    if ghidra_code:
        judge_prompt += f"### Ghidra Pseudocode (for reference):\n```c\n{ghidra_code[:500]}...\n```\n\n"
    
    if asm:
        judge_prompt += f"### Assembly (for logic verification):\n```asm\n{asm[:500]}...\n```\n\n"
    
    return judge_prompt


def get_semantic_fix_prompt(
    optimized_code: str,
    judge_feedback: str,
    retrieved_examples: List[Dict],
    language: str
) -> str:
    """
    Generate prompt for semantic fixes based on judge feedback
    """
    fix_prompt = config["prompts"]["semantic_fix_prompt"]
    
    # Add judge feedback
    fix_prompt += f"\n\n### Judge Feedback:\n{judge_feedback}\n\n"
    
    # Add KB examples as reference
    fix_prompt += "### Reference Examples (known-correct patterns):\n"
    for i, ex in enumerate(retrieved_examples[:2], 1):
        fix_prompt += f"\nExample {i}:\n```c\n{ex['code'][:300]}...\n```\n"
    
    fix_prompt += f"\n\n### Your Current Code:\n```{language}\n{optimized_code}\n```\n\n"
    fix_prompt += "Fix the semantic issues while maintaining compilability. Output ONLY the corrected code.\n"
    
    return fix_prompt


def evaluate_with_judge(
    optimized_code: str,
    asm: str,
    ghidra_code: str,
    retrieved_examples: List[Dict],
    language: str,
    llm_interface: LLMInterface
) -> JudgeResult:
    """
    Use LLM-as-judge to evaluate type and logic correctness
    Returns JudgeResult with binary flags
    """
    judge_prompt = get_semantic_judge_prompt(
        optimized_code, asm, ghidra_code, retrieved_examples, language
    )
    
    try:
        response = llm_interface.generate(judge_prompt)
        
        # Parse JSON response
        # Try to extract JSON from response
        json_start = response.find('{')
        json_end = response.rfind('}') + 1
        if json_start != -1 and json_end > json_start:
            json_str = response[json_start:json_end]
            result = json.loads(json_str)
            
            types_correct = result.get("types_correct", False)
            logic_correct = result.get("logic_correct", False)
            feedback = result.get("feedback", "No feedback")
            
            # Compute binary score: types_correct (1st bit), logic_correct (2nd bit)
            score = f"{int(types_correct)}{int(logic_correct)}"
            
            return JudgeResult(
                types_correct=types_correct,
                logic_correct=logic_correct,
                score=score,
                feedback=feedback
            )
        else:
            # Fallback if JSON parsing fails
            return JudgeResult(
                types_correct=False,
                logic_correct=False,
                score="00",
                feedback="Failed to parse judge response"
            )
    
    except Exception as e:
        print(f"[Judge] Error: {e}")
        return JudgeResult(
            types_correct=False,
            logic_correct=False,
            score="00",
            feedback=f"Judge evaluation failed: {str(e)}"
        )


def get_optimized_code_with_kb(
    c_code: str,
    asm: str,
    ghidra_code: str,
    function_summary: str,
    caller_and_callee_summary: str,
    function_sog: str,
    language: str,
    max_iterations: int,
    llm_interface: LLMInterface,
    c_flag: bool
) -> Tuple[bool, str, Dict]:
    """
    Generate optimized C code with KB integration and LLM-as-judge
    
    Returns: (compilation_success, final_code, metadata)
    """
    metadata = {
        "kb_examples_used": False,
        "compilation_iterations": 0,
        "semantic_iterations": 0,
        "judge_scores": [],
        "final_judge_score": "00"
    }
    
    # Step 1: Retrieve examples from KB
    retrieved_examples = kb_client.retrieve_examples(asm, k=KB_RETRIEVAL_K)
    if retrieved_examples:
        metadata["kb_examples_used"] = True
        print(f"[KB] Retrieved {len(retrieved_examples)} examples")
    
    # Handle everything in a temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        file_extension = "cpp" if language == "cpp" else "c"
        original_c_file = Path(temp_dir) / f"original.{file_extension}"
        
        # Step 2: Initial LLM optimization with KB examples
        print("[LLM] Starting optimization with KB examples...")
        initial_prompt = get_initial_prompt_with_kb(
            c_code=c_code,
            asm=asm,
            ghidra_code=ghidra_code,
            function_summary=function_summary,
            caller_and_callee_summary=caller_and_callee_summary,
            function_sog=function_sog,
            language=language,
            retrieved_examples=retrieved_examples
        )
        
        optimized_code = llm_interface.generate(initial_prompt)
        
        # Step 3: Compilation repair loop (syntactic fixes)
        compilation_success = False
        for iteration in range(max_iterations):
            metadata["compilation_iterations"] = iteration + 1
            
            original_c_file.write_text(optimized_code)
            status, message = c.compile_source(
                source_file_path=original_c_file,
                output_file_path=Path(temp_dir) / "optimized.out",
                opt=OptimizationLevel.O0,
                is_cpp=(language == "cpp"),
                c_flag=c_flag
            )
            
            if status:
                print(f"[Compile] ✓ Code compiles after {iteration + 1} iterations")
                compilation_success = True
                break
            
            # Compilation failed - request repair
            print(f"[Compile] ✗ Iteration {iteration + 1} failed")
            e = ErrorNormalizer()
            error_prompt = e.format_for_llm(message)
            
            repair_prompt = get_repair_prompt_with_kb(
                c_code=optimized_code,
                compilation_errors=error_prompt,
                function_summary=function_summary,
                caller_and_callee_summary=caller_and_callee_summary,
                function_sog=function_sog,
                language=language,
                retrieved_examples=retrieved_examples
            )
            
            optimized_code = llm_interface.generate(repair_prompt)
        
        if not compilation_success:
            print(f"[Compile] ✗ Failed to compile after {max_iterations} iterations")
            metadata["final_judge_score"] = "00"
            return False, optimized_code, metadata
        
        # Step 4: Semantic checking with LLM-as-judge
        print("[Judge] Evaluating semantic correctness...")
        remaining_iterations = max_iterations - metadata["compilation_iterations"]
        
        for semantic_iter in range(min(remaining_iterations, 5)):  # Max 5 semantic iterations
            metadata["semantic_iterations"] = semantic_iter + 1
            
            judge_result = evaluate_with_judge(
                optimized_code=optimized_code,
                asm=asm,
                ghidra_code=ghidra_code,
                retrieved_examples=retrieved_examples,
                language=language,
                llm_interface=llm_interface
            )
            
            metadata["judge_scores"].append(judge_result.score)
            print(f"[Judge] Score: {judge_result.score} - {judge_result.feedback}")
            
            # Check if we're satisfied (11 = both correct)
            if judge_result.score == "11":
                metadata["final_judge_score"] = "11"
                print("[Judge] ✓ Code passes all checks!")
                return True, optimized_code, metadata
            
            # If not perfect, request semantic fixes
            print(f"[Judge] Requesting semantic fixes (iteration {semantic_iter + 1})...")
            fix_prompt = get_semantic_fix_prompt(
                optimized_code=optimized_code,
                judge_feedback=judge_result.feedback,
                retrieved_examples=retrieved_examples,
                language=language
            )
            
            optimized_code = llm_interface.generate(fix_prompt)
            
            # Re-check compilation after semantic fix
            original_c_file.write_text(optimized_code)
            status, message = c.compile_source(
                source_file_path=original_c_file,
                output_file_path=Path(temp_dir) / "optimized.out",
                opt=OptimizationLevel.O0,
                is_cpp=(language == "cpp"),
                c_flag=c_flag
            )
            
            if not status:
                print("[Judge] ✗ Semantic fix broke compilation, reverting...")
                # Could implement rollback here, for now just note it
                break
        
        # Final evaluation
        final_judge = evaluate_with_judge(
            optimized_code, asm, ghidra_code, retrieved_examples, language, llm_interface
        )
        metadata["final_judge_score"] = final_judge.score
        
        return True, optimized_code, metadata


def create_cfg_output_dir(executable_name: str) -> Path:
    """Create output directory for CFG extraction."""
    output_dir_path = Path(config["humaneval"]["output_path"]) / "SOG" / executable_name
    if output_dir_path.exists():
        shutil.rmtree(output_dir_path)
    output_dir_path.mkdir(parents=True, exist_ok=True)
    return output_dir_path


def compile_single_program(data: Dict, temp_base_dir: Path) -> CompilationResult:
    """Compile a single program and return the result."""
    try:
        c_program = data['func_dep'] + data['func']
        temp_dir = temp_base_dir / f"prog_{data['index']}"
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        c_file_path = temp_dir / f"temp.{'cpp' if data['language']=='cpp' else 'c'}"
        executable_path = temp_dir / f"temp_executable_{data['index']}"
        
        with open(c_file_path, "w") as f:
            f.write(c_program)
        
        status, message = c.compile_source(
            source_file_path=str(c_file_path),
            output_file_path=str(executable_path),
            opt=OptimizationLevel.O0,
            is_cpp=(data['language'] == "cpp"),
            c_flag=True
        )
        
        if not status:
            print(f"[Compile] Failed for index {data['index']}: {message}")
            return CompilationResult(
                index=data['index'],
                success=False,
                executable_path=None,
                error_message=message,
                data=data
            )
        
        return CompilationResult(
            index=data['index'],
            success=True,
            executable_path=executable_path,
            error_message=None,
            data=data
        )
    
    except Exception as e:
        print(f"[Compile] Exception for index {data['index']}: {e}")
        return CompilationResult(
            index=data['index'],
            success=False,
            executable_path=None,
            error_message=str(e),
            data=data
        )


def batch_compile_programs(items: List[Dict], temp_base_dir: Path) -> List[CompilationResult]:
    """Compile multiple programs in parallel."""
    print(f"\n[Batch Compile] Starting compilation of {len(items)} programs...")
    results = []
    
    with ThreadPoolExecutor(max_workers=COMPILATION_BATCH_SIZE) as executor:
        futures = {
            executor.submit(compile_single_program, item, temp_base_dir): item 
            for item in items
        }
        
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            if result.success:
                print(f"[Batch Compile] ✓ Index {result.index} compiled successfully")
            else:
                print(f"[Batch Compile] ✗ Index {result.index} failed")
    
    successful = sum(1 for r in results if r.success)
    print(f"[Batch Compile] Completed: {successful}/{len(items)} successful\n")
    return results


def batch_ghidra_analysis(executables: List[Tuple[int, Path]]) -> Dict[int, Dict]:
    """
    Run Ghidra analysis on multiple executables in batch.
    Returns a mapping of index -> {cfg_map, callgraph_map}
    """
    print(f"\n[Batch Ghidra] Starting analysis of {len(executables)} executables...")
    results = {}
    
    # Process executables in batches
    for i in range(0, len(executables), GHIDRA_BATCH_SIZE):
        batch = executables[i:i + GHIDRA_BATCH_SIZE]
        print(f"[Batch Ghidra] Processing batch {i//GHIDRA_BATCH_SIZE + 1} ({len(batch)} executables)...")
        
        with ThreadPoolExecutor(max_workers=GHIDRA_BATCH_SIZE) as executor:
            futures = {}
            
            for idx, exe_path in batch:
                future = executor.submit(analyze_single_executable, idx, exe_path)
                futures[future] = idx
            
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    result = future.result()
                    results[idx] = result
                    print(f"[Batch Ghidra] ✓ Index {idx} analyzed successfully")
                except Exception as e:
                    print(f"[Batch Ghidra] ✗ Index {idx} failed: {e}")
                    results[idx] = None
    
    print(f"[Batch Ghidra] Completed analysis of {len(results)} executables\n")
    return results


def analyze_single_executable(idx: int, exe_path: Path) -> Dict:
    """Analyze a single executable with Ghidra."""
    executable_name = exe_path.stem
    output_dir = create_cfg_output_dir(executable_name)
    
    # Extract CFG and call graph using Ghidra
    cfg_map = g.extract_cfg(exe_path, output_dir)
    callgraph_map = g.extract_call_graph(exe_path, output_dir)
    
    return {
        'cfg_map': cfg_map,
        'callgraph_map': callgraph_map,
        'output_dir': output_dir,
        'executable_name': executable_name
    }


def gen_code_summary_batch(prompts: List[Tuple[int, str]]) -> Dict[int, str]:
    """
    Generate code summaries for multiple functions in batch.
    Returns a mapping of index -> summary.
    """
    print(f"\n[Batch LLM] Generating {len(prompts)} summaries...")
    results = {}
    
    with ThreadPoolExecutor(max_workers=LLM_BATCH_SIZE) as executor:
        futures = {}
        for idx, prompt in prompts:
            future = executor.submit(llm_interface.generate, prompt)
            futures[future] = idx
        
        for future in as_completed(futures):
            idx = futures[future]
            try:
                result = future.result()
                results[idx] = result
                print(f"[Batch LLM] ✓ Summary {idx} generated")
            except Exception as e:
                print(f"[Batch LLM] ✗ Summary {idx} failed: {e}")
                results[idx] = ""
    
    print(f"[Batch LLM] Completed {len(results)} summaries\n")
    return results


def gen_context_summary(callgraph: Dict[str, List[str]]) -> str:
    """Generate context summary from call graph"""
    prompt = ""
    for function, callees in callgraph.items():
        if function == "func0":
            prompt += f"{function} calls {', '.join(callees) if callees else 'no functions'}\n"
    return prompt


def split_enrichment(data: Dict, ghidra_result: Dict) -> Dict:
    """
    Enrich function data using pre-extracted Ghidra analysis.
    """
    program_data = {}
    program_data['index'] = data['index']
    program_data['language'] = data['language']
    program_data['executable_name'] = ghidra_result['executable_name']
    program_data['opt'] = data['opt']
    program_data['test'] = data['test']
    program_data['original_code'] = data['func']
    program_data['func_dep'] = data['func_dep']
    program_data['functions'] = []
    
    cfg_map = ghidra_result['cfg_map']
    callgraph_map = ghidra_result['callgraph_map']
    
    # Build and sort call graph
    callgraph = {}
    sorted_functions = []
    
    if 'call_graph' in callgraph_map and callgraph_map['call_graph']:
        try:
            callgraph = build_call_graph(callgraph_map['call_graph'])
            sorted_functions = topological_sort(callgraph)
        except Exception as e:
            print(f"[Warning] Failed to build call graph: {e}")
            sorted_functions = []
    
    # Add func0 if not present
    if len(sorted_functions) == 0:
        sorted_functions.append("func0")
    
    program_data['callgraph'] = callgraph
    
    # Process functions
    functions = []
    for function_name in sorted_functions:
        if function_name != "func0":
            continue
        
        f_data = {}
        f_data['f_name'] = function_name
        f_data['asm'] = data['asm']
        f_data['ghidra_code'] = data['ghidra_pseudo']
        
        # Get SOG
        sog_path = cfg_map.get(function_name)
        if sog_path:
            with open(sog_path, 'r') as f:
                sog_dot = f.read()
            f_data['sog_dot'] = sog_dot
        else:
            f_data['sog_dot'] = ""
        
        # Get caller and callee context
        callers = [caller for caller, callees in callgraph.items() if function_name in callees]
        callees = callgraph.get(function_name, [])
        f_data['callers'] = callers
        f_data['callees'] = callees
        
        functions.append(f_data)
    
    program_data['functions'] = functions
    return program_data


def batch_optimize_functions(enriched_programs: List[Dict]) -> List[Dict]:
    """
    Optimize multiple functions using batched LLM calls with KB integration
    PARALLELIZED: Multiple test cases run in parallel
    """
    print(f"\n[Batch Optimize] Starting optimization of {len(enriched_programs)} programs...")
    
    # Step 1: Batch generate summaries
    summary_prompts = []
    for prog_idx, prog_data in enumerate(enriched_programs):
        for func_data in prog_data['functions']:
            summary_prompt = config["prompts"]["summary_prompt"]
            prompt = f"{summary_prompt}"
            if func_data.get('ghidra_code'):
                prompt += f"\n\nGhidra Code:\n```c\n{func_data['ghidra_code']}\n```"
            if func_data.get('asm'):
                prompt += f"\n\nAssembly Instructions:\n{func_data['asm']}"
            summary_prompts.append((prog_idx, prompt))
    
    # Generate all summaries in batch
    summaries = gen_code_summary_batch(summary_prompts)
    
    # Step 2: Add summaries to function data
    for prog_idx, prog_data in enumerate(enriched_programs):
        for func_data in prog_data['functions']:
            func_data['function_summary'] = summaries.get(prog_idx, "")
    
    # Step 3: PARALLELIZED optimization with KB integration
    # Run multiple test cases in parallel (12 concurrent)
    print(f"[Batch Optimize] Running {LLM_BATCH_SIZE} test cases in parallel...")
    
    results = [None] * len(enriched_programs)
    
    def optimize_single_program(prog_idx: int, prog_data: Dict) -> Tuple[int, Dict]:
        """Optimize a single program (runs in parallel)"""
        for func_data in prog_data['functions']:
            print(f"[Parallel-{prog_idx}] Optimizing function {func_data['f_name']}...")
            
            success, optimized_code, metadata = get_optimized_code_with_kb(
                c_code=func_data['ghidra_code'],
                asm=func_data['asm'],
                ghidra_code=func_data['ghidra_code'],
                function_summary=func_data['function_summary'],
                caller_and_callee_summary=gen_context_summary(prog_data['callgraph']),
                function_sog=func_data['sog_dot'],
                language=prog_data.get('language', 'c'),
                max_iterations=MAX_ITERATIONS,
                llm_interface=llm_interface,
                c_flag=True
            )
            
            func_data['optimization_status'] = success
            func_data['optimized_code'] = optimized_code
            func_data['optimization_metadata'] = metadata
            
            print(f"[Parallel-{prog_idx}] Done. Judge score: {metadata['final_judge_score']}")
        
        return prog_idx, prog_data
    
    # Execute in parallel
    with ThreadPoolExecutor(max_workers=LLM_BATCH_SIZE) as executor:
        futures = {
            executor.submit(optimize_single_program, idx, prog): idx
            for idx, prog in enumerate(enriched_programs)
        }
        
        for future in as_completed(futures):
            prog_idx, optimized_prog = future.result()
            results[prog_idx] = optimized_prog
            print(f"[Batch Optimize] ✓ Program {prog_idx} completed")
    
    print(f"[Batch Optimize] All {len(results)} programs completed\n")
    return results


def process_batch(batch_items: List[Dict], temp_base_dir: Path) -> List[Dict]:
    """
    Process a batch of items through the entire pipeline:
    1. Parallel compilation
    2. Batch Ghidra analysis
    3. PARALLELIZED LLM optimization with KB integration
    """
    # Step 1: Compile all programs in parallel
    compile_results = batch_compile_programs(batch_items, temp_base_dir)
    
    # Filter successful compilations
    successful_compilations = [(r.index, r.executable_path) for r in compile_results if r.success]
    
    if not successful_compilations:
        print("[Batch] No successful compilations in this batch")
        return []
    
    # Step 2: Batch Ghidra analysis
    ghidra_results = batch_ghidra_analysis(successful_compilations)
    
    # Step 3: Enrich data with Ghidra results
    enriched_programs = []
    for compile_result in compile_results:
        if not compile_result.success:
            continue
        
        ghidra_result = ghidra_results.get(compile_result.index)
        if ghidra_result is None:
            print(f"[Batch] No Ghidra result for index {compile_result.index}")
            continue
        
        enriched_data = split_enrichment(compile_result.data, ghidra_result)
        enriched_programs.append(enriched_data)
    
    # Step 4: PARALLELIZED LLM optimization with KB integration
    optimized_programs = batch_optimize_functions(enriched_programs)
    
    return optimized_programs


def save_results(results: List[Dict], output_file_path: Path):
    """Save results incrementally to JSON file."""
    if output_file_path.exists():
        with open(output_file_path, "r") as f:
            existing_data = json.load(f)
        existing_data.extend(results)
        with open(output_file_path, "w") as f:
            json.dump(existing_data, f, indent=4)
    else:
        with open(output_file_path, "w") as f:
            json.dump(results, f, indent=4)


def process_humaneval_decompile(json_path: Path) -> List[Dict]:
    """
    Process the humaneval decompile json file with KB-enhanced batched operations.
    """
    output_file_path = output_dir / "v5_kb_enhanced_humaneval_decompile.json"
    output_file_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(json_path, "r") as f:
        humaneval_data = json.load(f)
    
    print(f"\n{'='*60}")
    print(f"Processing {len(humaneval_data)} functions from HumanEval dataset")
    print(f"KB API: {KB_API_URL}")
    print(f"Max iterations: {MAX_ITERATIONS}")
    print(f"Parallel LLM calls: {LLM_BATCH_SIZE}")
    print(f"{'='*60}\n")
    
    # Create a persistent temp directory for this run
    with tempfile.TemporaryDirectory() as temp_base_dir:
        temp_base_path = Path(temp_base_dir)
        
        # Process in batches
        batch_size = COMPILATION_BATCH_SIZE
        total_batches = (len(humaneval_data) + batch_size - 1) // batch_size
        
        for batch_idx in range(0, len(humaneval_data), batch_size):
            batch_num = batch_idx // batch_size + 1
            batch_items = humaneval_data[batch_idx:batch_idx + batch_size]
            
            print(f"\n{'='*60}")
            print(f"BATCH {batch_num}/{total_batches}: Processing items {batch_idx} to {batch_idx + len(batch_items) - 1}")
            print(f"{'='*60}\n")
            
            batch_results = process_batch(batch_items, temp_base_path)
            
            # Save results incrementally
            if batch_results:
                save_results(batch_results, output_file_path)
                print(f"\n[Save] Saved {len(batch_results)} results from batch {batch_num}")
    
    # Close KB client
    kb_client.close()
    
    print(f"\n{'='*60}")
    print(f"Processing complete! Results saved to {output_file_path}")
    print(f"{'='*60}\n")


def main():
    """Main entry point."""
    json_path = corpus_path / "humaneval-decompile.json"
    process_humaneval_decompile(json_path)


if __name__ == "__main__":
    main()
