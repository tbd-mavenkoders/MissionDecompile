"""
LLM Interface Class
A minimal interface for interacting with Large Language Models.

V7 Enhancement: Global rate limiting to prevent overwhelming the LLM server.
"""

import os
import time
import threading
from collections import deque
from typing import Optional
from abc import ABC, abstractmethod
import yaml
from pathlib import Path
from openai import RateLimitError
import openai
import re
import requests
import json


# =============================================================================
# GLOBAL RATE LIMITER (V7 Enhancement)
# =============================================================================

class RateLimiter:
    """
    Thread-safe rate limiter using a sliding window approach.
    Ensures requests don't exceed a specified rate per minute.
    """
    
    def __init__(self, max_requests_per_minute: int = 150):
        """
        Initialize the rate limiter.
        
        Args:
            max_requests_per_minute: Maximum number of requests allowed per minute
        """
        self.max_rpm = max_requests_per_minute
        self.window_size = 60.0  # seconds
        self.request_times = deque()  # Timestamps of recent requests
        self.lock = threading.Lock()
        self._enabled = True
        self._total_requests = 0
        self._total_wait_time = 0.0
    
    def set_rate(self, max_requests_per_minute: int):
        """Update the rate limit."""
        with self.lock:
            self.max_rpm = max_requests_per_minute
    
    def enable(self):
        """Enable rate limiting."""
        self._enabled = True
    
    def disable(self):
        """Disable rate limiting (for testing)."""
        self._enabled = False
    
    def wait_if_needed(self) -> float:
        """
        Wait if necessary to stay within rate limit.
        
        Returns:
            Time waited in seconds (0 if no wait needed)
        """
        if not self._enabled:
            return 0.0
        
        with self.lock:
            now = time.time()
            
            # Remove timestamps outside the window
            while self.request_times and self.request_times[0] < now - self.window_size:
                self.request_times.popleft()
            
            # Check if we're at the limit
            if len(self.request_times) >= self.max_rpm:
                # Calculate wait time until the oldest request falls outside window
                oldest = self.request_times[0]
                wait_time = (oldest + self.window_size) - now + 0.1  # Add 100ms buffer
                
                if wait_time > 0:
                    self._total_wait_time += wait_time
                    # Release lock while waiting
                    self.lock.release()
                    try:
                        time.sleep(wait_time)
                    finally:
                        self.lock.acquire()
                    
                    # Re-clean after waiting
                    now = time.time()
                    while self.request_times and self.request_times[0] < now - self.window_size:
                        self.request_times.popleft()
                    
                    return wait_time
            
            # Record this request
            self.request_times.append(now)
            self._total_requests += 1
            return 0.0
    
    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        with self.lock:
            return {
                "total_requests": self._total_requests,
                "total_wait_time_seconds": round(self._total_wait_time, 2),
                "current_window_requests": len(self.request_times),
                "max_rpm": self.max_rpm,
                "enabled": self._enabled
            }
    
    def current_rate(self) -> int:
        """Get current requests in the sliding window."""
        with self.lock:
            now = time.time()
            # Clean old entries
            while self.request_times and self.request_times[0] < now - self.window_size:
                self.request_times.popleft()
            return len(self.request_times)


# Global rate limiter instance (configurable)
# Default: 150 requests per minute
GLOBAL_RATE_LIMITER = RateLimiter(max_requests_per_minute=150)


def set_global_rate_limit(max_requests_per_minute: int):
    """
    Set the global LLM rate limit.
    
    Args:
        max_requests_per_minute: Maximum requests per minute (e.g., 150)
    """
    GLOBAL_RATE_LIMITER.set_rate(max_requests_per_minute)
    print(f"[RateLimiter] Set global rate limit to {max_requests_per_minute} requests/minute")


def get_rate_limiter_stats() -> dict:
    """Get statistics from the global rate limiter."""
    return GLOBAL_RATE_LIMITER.get_stats()



# Config.yaml paths
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.yaml"
print(f"Loading config from: {CONFIG_PATH}")

with open(CONFIG_PATH, "r") as f:
    config = yaml.safe_load(f)


def clean_llm_output(code: str) -> str:
  """
  Remove Markdown code fences and language tags like ```c or ```cpp from LLM output.
  """
  code = re.sub(r"^```[a-zA-Z0-9]*\s*", "", code.strip())  # remove opening ```c or ```cpp
  code = re.sub(r"```$", "", code.strip())  # remove closing ```
  return code.strip()


class LLMInterface(ABC):
    """Abstract base class for LLM interactions."""
    def __init__(
        self,
        model_name: str,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        api_key: Optional[str] = None,
    ):
        """
        Initialize the LLM interface.
        
        Args:
            model_name: Name of the model to use
            temperature: Sampling temperature (0.0 to 1.0)
            max_tokens: Maximum number of tokens in the response
            api_key: API key for the service (if None, reads from environment)
        """
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.api_key = api_key
    
    @abstractmethod
    def generate(self, prompt: str) -> str:
        pass


class OpenAIInterface(LLMInterface):
    """
    Interface for OpenAI models (GPT-3.5, GPT-4, etc.)
    """
    
    def __init__(
        self,
        model_name: str = "gpt-3.5-turbo",
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        api_key: Optional[str] = None,
    ):
        super().__init__(model_name, temperature, max_tokens, api_key)
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.client = openai.OpenAI(api_key=self.api_key)

          
          
    def generate(self, prompt: str) -> str:
        """
        Generate response using OpenAI API.
        """
        messages = [{"role": "user", "content": prompt}]
        
        params = {
            "model": self.model_name,
            "messages": messages,
            "temperature": self.temperature,
        }
        
        if self.max_tokens:
            params["max_tokens"] = self.max_tokens
        
        try:
          response = self.client.chat.completions.create(**params)
        except Exception as e:
          raise e

          
        return clean_llm_output(response.choices[0].message.content)


class GeminiInterface(LLMInterface):
    """
    Interface for Google Gemini models
    """
    def __init__(
        self,
        model_name: str = "gemini-pro",
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        api_key: Optional[str] = None,
    ):
        super().__init__(model_name, temperature, max_tokens, api_key)
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            
            generation_config = {
                "temperature": self.temperature,
            }
            
            if self.max_tokens:
                generation_config["max_output_tokens"] = self.max_tokens
          
            
            self.model = genai.GenerativeModel(
                model_name=self.model_name,
                generation_config=generation_config
            )
        except ImportError:
            raise ImportError("Please install google-generativeai: pip install google-generativeai")
    
    def generate(self, prompt: str) -> str:
        """
        Generate response using Google Gemini API.
        Handles empty or filtered responses safely.
        """
        try:
            
            response = self.model.generate_content(prompt)
            
            # Some responses might not have .text even if generation succeeded.
            if not hasattr(response, "candidates") or not response.candidates:
                print("No candidates returned from Gemini. Retrying once...")
                response = self.model.generate_content(prompt)
            
            # Still no valid candidate → return empty safely.
            if not hasattr(response, "candidates") or not response.candidates:
                print("No valid candidates after retry.")
                return ""
            
            # Extract text safely from first candidate.
            candidate = response.candidates[0]
            if not candidate or not candidate.content.parts:
                print("Candidate has no text parts.")
                return ""
            
            # Join all text parts safely.
            text_parts = []
            for part in candidate.content.parts:
                if hasattr(part, "text") and part.text:
                    text_parts.append(part.text)
            
            if not text_parts:
                print("No text content found in response parts.")
                return ""

            return clean_llm_output("\n".join(text_parts))
        
        except Exception as e:
            print(f"[GeminiInterface] Error: {e}")
            return ""


class VLLMInterface(LLMInterface):
    """
    Interface for vLLM OpenAI GPT-OSS models.
    
    V7 Enhancement: Uses global rate limiter to prevent overwhelming the server.
    """
    def __init__(
        self,
        model_name: str = "openai/gpt-oss-20b",
        temperature: float = 1.0,
        max_tokens: Optional[int] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        super().__init__(model_name, temperature, max_tokens, api_key)
        # vLLM endpoint
        self.base_url = base_url or os.getenv("VLLM_BASE_URL", "http://192.168.41.119:10011")
        self.api_endpoint = f"{self.base_url}/v1/responses"
    
    def generate(self, prompt: str, max_retries: int = 3, return_reasoning: bool = False):
        """
        Generate response using vLLM OpenAI API.
        Makes HTTP POST request to vLLM server.
        
        V7 Enhancement: Applies global rate limiting before each request.
        V7.1 Enhancement: Captures reasoning tokens alongside output.
        
        Args:
            prompt: The prompt to send to the model
            max_retries: Number of retries on failure (default: 3)
            return_reasoning: If True, returns dict with 'output' and 'reasoning' keys
            
        Returns:
            If return_reasoning=False: Generated text response (str)
            If return_reasoning=True: Dict with 'output', 'reasoning', 'usage' keys
            
        Raises:
            RuntimeError: If all retries fail or no valid response received
        """
        last_error = None
        
        for attempt in range(max_retries):
            try:
                # V7: Apply rate limiting before making the request
                wait_time = GLOBAL_RATE_LIMITER.wait_if_needed()
                if wait_time > 0:
                    current_rate = GLOBAL_RATE_LIMITER.current_rate()
                    print(f"[VLLMInterface] Rate limited, waited {wait_time:.1f}s (current: {current_rate}/{GLOBAL_RATE_LIMITER.max_rpm} rpm)")
                
                payload = {
                    "model": self.model_name,
                    "input": prompt,
                }
                
                # Add optional parameters if specified
                if self.temperature is not None:
                    payload["temperature"] = self.temperature
                if self.max_tokens:
                    payload["max_output_tokens"] = self.max_tokens
                
                # Make POST request to vLLM server
                response = requests.post(
                    self.api_endpoint,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=600  # 10 minute timeout 
                )
                
                response.raise_for_status()
                result = response.json()
                
                # V7.1: Extract both reasoning and output text
                output_text = None
                reasoning_text = None
                usage_info = result.get("usage", {})
                
                # Extract the response text from output array
                if "output" in result and isinstance(result["output"], list):
                    for output_item in result["output"]:
                        # Extract reasoning (type="reasoning")
                        if output_item.get("type") == "reasoning" and "content" in output_item:
                            for content_item in output_item["content"]:
                                if content_item.get("type") == "reasoning_text" and "text" in content_item:
                                    reasoning_text = content_item["text"]
                        
                        # Extract output (type="message", role="assistant")
                        if (output_item.get("type") == "message" and 
                            output_item.get("role") == "assistant" and
                            "content" in output_item):
                            for content_item in output_item["content"]:
                                if content_item.get("type") == "output_text" and "text" in content_item:
                                    output_text = clean_llm_output(content_item["text"])
                
                if output_text and output_text.strip():
                    if return_reasoning:
                        return {
                            "output": output_text,
                            "reasoning": reasoning_text,
                            "usage": usage_info
                        }
                    return output_text
                
                last_error = f"No valid response in result (attempt {attempt + 1})"
                print(f"[VLLMInterface] {last_error}")
                
            except requests.exceptions.Timeout:
                last_error = f"Request timeout (attempt {attempt + 1})"
                print(f"[VLLMInterface] {last_error}")
            except requests.exceptions.RequestException as e:
                last_error = f"Request error: {e} (attempt {attempt + 1})"
                print(f"[VLLMInterface] {last_error}")
            except json.JSONDecodeError as e:
                last_error = f"JSON decode error: {e} (attempt {attempt + 1})"
                print(f"[VLLMInterface] {last_error}")
            except Exception as e:
                last_error = f"Error: {e} (attempt {attempt + 1})"
                print(f"[VLLMInterface] {last_error}")
            
            # Wait before retry (exponential backoff)
            if attempt < max_retries - 1:
                import time
                wait_time = 2 ** attempt
                print(f"[VLLMInterface] Retrying in {wait_time}s...")
                time.sleep(wait_time)
        
        # All retries failed - raise exception instead of returning empty
        raise RuntimeError(f"[VLLMInterface] All {max_retries} attempts failed: {last_error}")


class OllamaInterface(LLMInterface):
    """
    Interface for Ollama models (local or remote)
    """
    def __init__(
        self,
        model_name: str = "gpt-oss:20b",
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        super().__init__(model_name, temperature, max_tokens, api_key)
        # Ollama doesn't use API keys, but we keep the parameter for consistency
        # base_url is the Ollama server endpoint
        self.base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.api_endpoint = f"{self.base_url}/api/generate"
    
    def generate(self, prompt: str) -> str:
        """
        Generate response using Ollama API.
        Makes HTTP POST request to Ollama server.
        """
        try:
            payload = {
                "model": self.model_name,
                "prompt": prompt,
                "stream": False,
            }
            
            # Add optional parameters if specified
            options = {}
            if self.temperature is not None:
                options["temperature"] = self.temperature
            if self.max_tokens:
                options["num_predict"] = self.max_tokens
            
            if options:
                payload["options"] = options
            
            # Make POST request to Ollama server
            response = requests.post(
                self.api_endpoint,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=600  # 5 minute timeout for large models
            )
            
            response.raise_for_status()
            result = response.json()
            
            # Extract the response text
            if "response" in result:
                return clean_llm_output(result["response"])
            else:
                print(f"[OllamaInterface] No response field in result: {result}")
                return ""
        
        except requests.exceptions.Timeout:
            print(f"[OllamaInterface] Request timeout for model {self.model_name}")
            return ""
        except requests.exceptions.RequestException as e:
            print(f"[OllamaInterface] Request error: {e}")
            return ""
        except json.JSONDecodeError as e:
            print(f"[OllamaInterface] JSON decode error: {e}")
            return ""
        except Exception as e:
            print(f"[OllamaInterface] Error: {e}")
            return ""



def create_llm_interface(
    provider: str,
    model_name: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
) -> LLMInterface:
    """
    Factory function to create an LLM interface.
    """
    providers = {
        'openai': OpenAIInterface,
        'gemini': GeminiInterface,
        'ollama': OllamaInterface,
        'vllm': VLLMInterface,
    }
    
    if provider.lower() not in providers:
        raise ValueError(
            f"Unknown provider: {provider}. "
            f"Available providers: {list(providers.keys())}"
        )
    
    interface_class = providers[provider.lower()]
    
    # For Ollama and vLLM, pass base_url if provided
    if provider.lower() in ['ollama', 'vllm'] and base_url:
        return interface_class(model_name=model_name, api_key=api_key, base_url=base_url)
    
    return interface_class(model_name=model_name, api_key=api_key)

