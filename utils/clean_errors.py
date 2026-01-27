'''
Normalizes compiler error messages for LLM-based code repair.
'''

import re
from typing import List, Dict, Tuple, Optional
from pathlib import Path


class ErrorNormalizer:
    """
    Normalizes compiler error messages for LLM consumption.
    """
    def __init__(self):
        # Common patterns in error messages to normalize
        self.file_path_pattern = re.compile(r'(/[^\s:]+|[A-Za-z]:\\[^\s:]+|[\w/\-\.]+\.[ch]pp?)')
        self.line_col_pattern = re.compile(r':(\d+):(\d+):')
        self.temp_file_pattern = re.compile(r'/tmp/[\w\-]+/|tmp[\w\-]+/')
        
        # Error type patterns
        self.error_types = {
            'syntax': re.compile(r'(syntax error|expected .* before|unexpected token)', re.IGNORECASE),
            'undefined': re.compile(r'(undefined reference|implicit declaration|undeclared)', re.IGNORECASE),
            'type': re.compile(r'(incompatible types|invalid conversion|type mismatch)', re.IGNORECASE),
            'redefinition': re.compile(r'(redefinition|redeclared|multiple definition)', re.IGNORECASE),
            'warning': re.compile(r'\bwarning:', re.IGNORECASE),
            'error': re.compile(r'\berror:', re.IGNORECASE),
        }
        
    def normalize_error(self, error_message: str, 
                       include_line_numbers: bool = True,
                       simplify_paths: bool = True,
                       categorize_errors: bool = True) -> str:
        """
        Normalizes error messages for consistent LLM processing.
        Args:
            error_message: The original error message string
            include_line_numbers: Whether to keep line:column numbers
            simplify_paths: Whether to simplify file paths to basenames
            categorize_errors: Whether to add error type categories
        Returns:
            Normalized error message string
        """
        if not error_message or error_message.strip() == "":
            return "No error message provided"
        
        # Remove common prefix patterns
        normalized = self.remove_unwanted_prefix(error_message)
        # Simplify file paths if requested
        if simplify_paths:
            normalized = self.simplify_paths(normalized)
        # Optionally remove line numbers
        if not include_line_numbers:
            normalized = self.remove_line_numbers(normalized)
        # Clean up whitespace and formatting
        normalized = self.clean_whitespace(normalized)
        # Remove duplicate lines
        normalized = self.remove_duplicates(normalized)
        # Categorize if requested
        if categorize_errors:
            normalized = self.add_categories(normalized)
        return normalized.strip()
    
    def parse_errors(self, error_message: str) -> List[Dict[str, any]]:
        """
        Parse error messages into structured format for LLMs.
        Args:
            error_message: Raw error message string  
        Returns:
            List of dictionaries containing parsed error information
        """
        errors = []
        lines = error_message.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
                
            error_info = self.parse_single_error(line)
            if error_info:
                errors.append(error_info)
        
        return errors
    
    def format_for_llm(self, error_message: str, 
                      source_code: Optional[str] = None,
                      max_errors: int = 50) -> str:
        """
        Format error messages specifically for LLM prompts.
        
        Args:
            error_message: Raw error message
            source_code: Optional source code context
            max_errors: Maximum number of errors to include
            
        Returns:
            Formatted string ready for LLM prompts
        """
        # Parse and normalize errors
        parsed_errors = self.parse_errors(error_message)
        
        # Limit number of errors
        if len(parsed_errors) > max_errors:
            parsed_errors = parsed_errors[:max_errors]
        
        # Build formatted output
        formatted_parts = []
        
        if parsed_errors:
            formatted_parts.append("## Compilation Errors:")
            for idx, error in enumerate(parsed_errors, 1):
                error_str = self.format_single_error(error, idx)
                formatted_parts.append(error_str)
        else:
            # Fallback to normalized message
            normalized = self.normalize_error(error_message)
            formatted_parts.append("## Compilation Error:")
            formatted_parts.append(normalized)
        
        if source_code:
            formatted_parts.append("\n## Source Code:")
            formatted_parts.append("```c")
            formatted_parts.append(source_code.strip())
            formatted_parts.append("```")
        
        return "\n".join(formatted_parts)
    
    def extract_error_locations(self, error_message: str) -> List[Tuple[str, int, int]]:
        """
        Extract file locations from error messages.
        Args:
            error_message: Raw error message
        Returns:
            List of tuples: (filename, line_number, column_number)
        """
        locations = []
        
        # Pattern: filename:line:col:
        pattern = re.compile(r'([^\s:]+\.c(?:pp)?):(\d+):(\d+):')
        
        for match in pattern.finditer(error_message):
            filename = match.group(1)
            line = int(match.group(2))
            col = int(match.group(3))
            locations.append((filename, line, col))
        
        return locations
    
    # Private helper methods
    
    def remove_unwanted_prefix(self, message: str) -> str:
        """
        Remove common prefixes like 'Compilation Failed :
        '"""
        prefixes = [
            'Compilation Failed:',
            'Compilation Failed :',
            'Error:',
            'Error :',
        ]
        for prefix in prefixes:
            if message.startswith(prefix):
                return message[len(prefix):].strip()
        
        return message
    
    def simplify_paths(self, message: str) -> str:
        """
        Replace full paths with just filenames
        """
        # Replace temp directories
        message = self.temp_file_pattern.sub('', message)
        
        # Simplify file paths to basename
        def replace_path(match):
            path = match.group(0)
            # Keep the basename
            return Path(path).name if '/' in path or '\\' in path else path
        
        return self.file_path_pattern.sub(replace_path, message)
    
    def remove_line_numbers(self, message: str) -> str:
        """
        Remove line:column: references
        """
        return self.line_col_pattern.sub(':', message)
    
    def clean_whitespace(self, message: str) -> str:
        """
        Clean up excessive whitespace
        """
        # Replace multiple spaces with single space
        message = re.sub(r' +', ' ', message)
        # Replace multiple newlines with double newline
        message = re.sub(r'\n\s*\n\s*\n+', '\n\n', message)
        return message.strip()
    
    def remove_duplicates(self, message: str) -> str:
        """
        Remove duplicate error lines
        """
        lines = message.split('\n')
        seen = set()
        unique_lines = []
        
        for line in lines:
            # Normalize line for comparison
            normalized_line = re.sub(r'\d+', 'N', line).strip()
            if normalized_line not in seen or not normalized_line:
                seen.add(normalized_line)
                unique_lines.append(line)
        
        return '\n'.join(unique_lines)
    
    def add_categories(self, message: str) -> str:
        """
        Add error type categories to help LLM understand error types
        """
        categorized_lines = []
        
        for line in message.split('\n'):
            if not line.strip():
                categorized_lines.append(line)
                continue
            
            # Check error type
            error_type = self.detect_error_type(line)
            if error_type and error_type not in line.lower():
                line = f"[{error_type.upper()}] {line}"
            
            categorized_lines.append(line)
        
        return '\n'.join(categorized_lines)
    
    def detect_error_type(self, line: str) -> Optional[str]:
        """Detect the type of error from a line"""
        for error_type, pattern in self.error_types.items():
            if pattern.search(line):
                return error_type
        return None
    
    def parse_single_error(self, line: str) -> Optional[Dict[str, any]]:
        """
        Parse a single error line into structured format
        """
        # Try to match: filename:line:col: type: message
        match = re.match(r'([^\s:]+\.c(?:pp)?):(\d+):(\d+):\s*(error|warning|note):\s*(.+)', line)
        
        if match:
            return {
                'file': match.group(1),
                'line': int(match.group(2)),
                'column': int(match.group(3)),
                'type': match.group(4),
                'message': match.group(5).strip(),
                'raw': line
            }
        
        # Fallback: just return the line as message
        if 'error' in line.lower() or 'warning' in line.lower():
            return {
                'file': None,
                'line': None,
                'column': None,
                'type': 'error' if 'error' in line.lower() else 'warning',
                'message': line.strip(),
                'raw': line
            }
        
        return None
    
    def format_single_error(self, error: Dict[str, any], index: int) -> str:
        """
        Format a single parsed error for LLM
        """
        parts = [f"\n{index}. "]
        
        if error['file'] and error['line']:
            parts.append(f"**{error['file']}:{error['line']}:{error['column']}**")
        
        if error['type']:
            parts.append(f"[{error['type'].upper()}]")
        
        parts.append(error['message'])
        
        return " ".join(parts)


def normalize_error(error_message: str) -> str:
    """
    Convenience function for basic error normalization.
    Args:
        error_message: The original error message string.
    Returns:
        Normalized error message string.
    """
    normalizer = ErrorNormalizer()
    return normalizer.normalize_error(error_message)
