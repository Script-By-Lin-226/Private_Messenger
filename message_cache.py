import time
import json
from typing import Dict, List, Optional, Any
from collections import OrderedDict
import logging

logger = logging.getLogger(__name__)

class MessageCache:
    """In-memory cache for messages to improve performance"""
    
    def __init__(self, max_size: int = 1000, ttl: int = 300):
        """
        Initialize message cache
        
        Args:
            max_size: Maximum number of cached conversations
            ttl: Time to live for cached items in seconds
        """
        self.max_size = max_size
        self.ttl = ttl
        self.cache: OrderedDict = OrderedDict()
        self.timestamps: Dict[str, float] = {}
        
    def _cleanup_expired(self):
        """Remove expired cache entries"""
        current_time = time.time()
        expired_keys = [
            key for key, timestamp in self.timestamps.items()
            if current_time - timestamp > self.ttl
        ]
        
        for key in expired_keys:
            self.cache.pop(key, None)
            self.timestamps.pop(key, None)
    
    def get(self, conversation_key: str) -> Optional[List[Dict[str, Any]]]:
        """
        Get cached messages for a conversation
        
        Args:
            conversation_key: Unique key for the conversation
            
        Returns:
            Cached messages or None if not found/expired
        """
        self._cleanup_expired()
        
        if conversation_key in self.cache:
            # Update timestamp and move to end (LRU)
            self.timestamps[conversation_key] = time.time()
            self.cache.move_to_end(conversation_key)
            return self.cache[conversation_key]
        
        return None
    
    def set(self, conversation_key: str, messages: List[Dict[str, Any]]):
        """
        Cache messages for a conversation
        
        Args:
            conversation_key: Unique key for the conversation
            messages: List of messages to cache
        """
        self._cleanup_expired()
        
        # Remove oldest entry if cache is full
        if len(self.cache) >= self.max_size:
            oldest_key = next(iter(self.cache))
            self.cache.pop(oldest_key)
            self.timestamps.pop(oldest_key, None)
        
        # Add new entry
        self.cache[conversation_key] = messages
        self.timestamps[conversation_key] = time.time()
        self.cache.move_to_end(conversation_key)
        
        logger.debug(f"Cached {len(messages)} messages for conversation {conversation_key}")
    
    def invalidate(self, conversation_key: str):
        """Remove a specific conversation from cache"""
        self.cache.pop(conversation_key, None)
        self.timestamps.pop(conversation_key, None)
        logger.debug(f"Invalidated cache for conversation {conversation_key}")
    
    def clear(self):
        """Clear all cached data"""
        self.cache.clear()
        self.timestamps.clear()
        logger.info("Message cache cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        self._cleanup_expired()
        return {
            'total_conversations': len(self.cache),
            'max_size': self.max_size,
            'ttl': self.ttl,
            'memory_usage_mb': sum(
                len(json.dumps(msgs)) for msgs in self.cache.values()
            ) / (1024 * 1024)
        }

class ConversationCache:
    """Cache for conversation metadata"""
    
    def __init__(self, max_size: int = 500, ttl: int = 600):
        """
        Initialize conversation cache
        
        Args:
            max_size: Maximum number of cached conversations
            ttl: Time to live for cached items in seconds
        """
        self.max_size = max_size
        self.ttl = ttl
        self.cache: OrderedDict = OrderedDict()
        self.timestamps: Dict[str, float] = {}
    
    def _cleanup_expired(self):
        """Remove expired cache entries"""
        current_time = time.time()
        expired_keys = [
            key for key, timestamp in self.timestamps.items()
            if current_time - timestamp > self.ttl
        ]
        
        for key in expired_keys:
            self.cache.pop(key, None)
            self.timestamps.pop(key, None)
    
    def get(self, user_id: str) -> Optional[List[Dict[str, Any]]]:
        """Get cached conversations for a user"""
        self._cleanup_expired()
        
        if user_id in self.cache:
            self.timestamps[user_id] = time.time()
            self.cache.move_to_end(user_id)
            return self.cache[user_id]
        
        return None
    
    def set(self, user_id: str, conversations: List[Dict[str, Any]]):
        """Cache conversations for a user"""
        self._cleanup_expired()
        
        if len(self.cache) >= self.max_size:
            oldest_key = next(iter(self.cache))
            self.cache.pop(oldest_key)
            self.timestamps.pop(oldest_key, None)
        
        self.cache[user_id] = conversations
        self.timestamps[user_id] = time.time()
        self.cache.move_to_end(user_id)
    
    def invalidate_user(self, user_id: str):
        """Invalidate cache for a specific user"""
        self.cache.pop(user_id, None)
        self.timestamps.pop(user_id, None)
    
    def clear(self):
        """Clear all cached data"""
        self.cache.clear()
        self.timestamps.clear()

# Global cache instances
message_cache = MessageCache()
conversation_cache = ConversationCache()

def get_conversation_key(user1_id: str, user2_id: str) -> str:
    """Generate a consistent conversation key for two users"""
    # Sort IDs to ensure consistent key regardless of sender/receiver order
    sorted_ids = sorted([user1_id, user2_id])
    return f"{sorted_ids[0]}_{sorted_ids[1]}"

def cache_messages(user1_id: str, user2_id: str, messages: List[Dict[str, Any]]):
    """Cache messages for a conversation"""
    conversation_key = get_conversation_key(user1_id, user2_id)
    message_cache.set(conversation_key, messages)

def get_cached_messages(user1_id: str, user2_id: str) -> Optional[List[Dict[str, Any]]]:
    """Get cached messages for a conversation"""
    conversation_key = get_conversation_key(user1_id, user2_id)
    return message_cache.get(conversation_key)

def invalidate_conversation_cache(user1_id: str, user2_id: str):
    """Invalidate cache for a specific conversation"""
    conversation_key = get_conversation_key(user1_id, user2_id)
    message_cache.invalidate(conversation_key)
