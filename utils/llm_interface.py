"""
LLM Interface Class
A minimal interface for interacting with Large Language Models.
"""

import os
from typing import Optional
from abc import ABC, abstractmethod
import yaml
from pathlib import Path
from openai import RateLimitError
import openai
import re
import requests
import json



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
    Interface for vLLM OpenAI GPT-OSS models
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
    
    def generate(self, prompt: str) -> str:
        """
        Generate response using vLLM OpenAI API.
        Makes HTTP POST request to vLLM server.
        """
        try:
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
                timeout=600  # 10 minute timeout for large models
            )
            
            response.raise_for_status()
            result = response.json()
            
            # Extract the response text from output array
            # Looking for the message type output with role="assistant"
            if "output" in result and isinstance(result["output"], list):
                for output_item in result["output"]:
                    if (output_item.get("type") == "message" and 
                        output_item.get("role") == "assistant" and
                        "content" in output_item):
                        # Extract text from content array
                        for content_item in output_item["content"]:
                            if content_item.get("type") == "output_text" and "text" in content_item:
                                return clean_llm_output(content_item["text"])
            
            print(f"[VLLMInterface] No valid response found in result: {result}")
            return ""
        
        except requests.exceptions.Timeout:
            print(f"[VLLMInterface] Request timeout for model {self.model_name}")
            return ""
        except requests.exceptions.RequestException as e:
            print(f"[VLLMInterface] Request error: {e}")
            return ""
        except json.JSONDecodeError as e:
            print(f"[VLLMInterface] JSON decode error: {e}")
            return ""
        except Exception as e:
            print(f"[VLLMInterface] Error: {e}")
            return ""


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

