"""
Context Manager for SASTRA agent
Handles token estimation and conversation history compression
"""
from typing import List, Dict, Any


class ContextManager:
    """Manages conversation context and compression"""
    
    def __init__(self, llm_client, max_tokens: int, compression_threshold: int = 90):
        """
        Initialize context manager
        
        Args:
            llm_client: LangChain-compatible LLM client for compression operations
            max_tokens: Maximum tokens before compression
            compression_threshold: Percentage threshold for compression (default: 90)
        """
        self.llm_client = llm_client
        self.max_tokens = max_tokens
        compression_threshold_percent = compression_threshold / 100.0
        self.compression_threshold = int(max_tokens * compression_threshold_percent)

    def estimate_tokens(self, text: str) -> int:
        """
        Estimate token count for text
        
        Args:
            text: Text to estimate
            
        Returns:
            Estimated token count (rough: 1 token ≈ 4 chars)
        """
        return len(text) // 4
    
    def estimate_conversation_tokens(self, messages: List[Dict[str, str]]) -> int:
        """
        Estimate total tokens in conversation history
        
        Args:
            messages: List of message dictionaries
            
        Returns:
            Total estimated tokens
        """
        total = 0
        for msg in messages:
            content = msg.get("content", "")
            if isinstance(content, str):
                total += self.estimate_tokens(content)
            elif isinstance(content, list):
                # Handle structured content
                for item in content:
                    if isinstance(item, dict) and "text" in item:
                        total += self.estimate_tokens(item["text"])
        return total
    
    def needs_compression(self, messages: List[Dict[str, str]]) -> bool:
        """
        Check if conversation history needs compression
        
        Args:
            messages: Conversation history
            
        Returns:
            True if compression needed
        """
        total_tokens = self.estimate_conversation_tokens(messages)
        return total_tokens > self.compression_threshold
    
    def compress_history(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Compress conversation history by summarizing old messages
        
        Args:
            messages: Full conversation history
            
        Returns:
            Compressed conversation history
        """
        if len(messages) <= 4:
            # Not enough to compress
            return messages
        
        # Keep first message (initial prompt) and last 3 exchanges (6 messages)
        keep_first = messages[:1]
        keep_last = messages[-6:] if len(messages) >= 6 else messages
        
        # Messages to summarize (middle section)
        to_summarize = messages[1:-6] if len(messages) > 7 else []
        
        if not to_summarize:
            return messages
        
        # Summarize middle section using central LLM client
        summary = self.llm_client.summarize_exploration(to_summarize)
        
        # Reconstruct history
        compressed = keep_first + [
            {
                "role": "user",
                "content": f"[PREVIOUS EXPLORATION SUMMARY]\n{summary}\n[END SUMMARY]"
            }
        ] + keep_last
        
        return compressed
    
    def compress_initial_context(self, context: str, max_tokens: int = 50000) -> str:
        """
        Compress initial CVE context before sending to agent
        
        Args:
            context: Full CVE context
            max_tokens: Target token count
            
        Returns:
            Compressed context
        """
        return self.llm_client.compress_context(context, max_tokens)
    
    def prepare_initial_prompt(self, cve_context: str, environment_details: str) -> str:
        """
        Prepare initial prompt with compressed CVE context
        
        Args:
            cve_context: Full CVE context from database
            environment_details: Environment information (project dir, git tag, etc.)
            
        Returns:
            Prepared prompt with compressed context
        """
        # Compress CVE context if needed
        current_tokens = self.estimate_tokens(cve_context)
        
        if current_tokens > 50000:
            compressed_context = self.compress_initial_context(cve_context, max_tokens=50000)
            print(f"Compression complete. Before: ~{current_tokens}, New: ~{self.estimate_tokens(compressed_context)} tokens")
        else:
            compressed_context = cve_context
        
        # Combine with environment details
        full_prompt = f"""You are provided with the following CVE context and project environment.

{compressed_context}

<environment>
{environment_details}
</environment>

Your task: Locate the exact vulnerable code segment in the target project directory that is responsible for this CVE.
"""
        
        return full_prompt
