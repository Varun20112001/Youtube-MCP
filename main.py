from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv
import os
import json
import aiohttp
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging
import base64
import secrets
import urllib.parse
from dataclasses import dataclass

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

mcp = FastMCP(
    name="YouTube Data Provider",
    description="An MCP server that provides comprehensive YouTube data including watch history, video details, trending content, and search capabilities. Designed for LLM-based analysis and intelligent recommendation generation.",
)

# YouTube Data API configuration
YOUTUBE_API_KEY = os.getenv('YOUTUBE_API_KEY')
YOUTUBE_CLIENT_ID = os.getenv('YOUTUBE_CLIENT_ID')
YOUTUBE_CLIENT_SECRET = os.getenv('YOUTUBE_CLIENT_SECRET')
YOUTUBE_REDIRECT_URI = os.getenv('YOUTUBE_REDIRECT_URI', 'http://localhost:8080/oauth/callback')
YOUTUBE_BASE_URL = "https://www.googleapis.com/youtube/v3"
YOUTUBE_OAUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
YOUTUBE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# YouTube API scopes for accessing user data
YOUTUBE_SCOPES = [
    "https://www.googleapis.com/auth/youtube.readonly",
    "https://www.googleapis.com/auth/youtube"
]

@dataclass
class OAuthState:
    """Represents OAuth state for a user authentication session"""
    state: str
    user_id: str
    created_at: datetime
    
@dataclass 
class UserToken:
    """Represents user's OAuth tokens"""
    access_token: str
    refresh_token: str
    expires_at: datetime
    user_id: str

class YouTubeOAuthManager:
    """Manages YouTube OAuth 2.0 authentication flow"""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.oauth_states: Dict[str, OAuthState] = {}
        self.user_tokens: Dict[str, UserToken] = {}
    
    def generate_auth_url(self, user_id: str) -> Dict[str, str]:
        """Generate OAuth authorization URL for user login"""
        state = secrets.token_urlsafe(32)
        
        # Store OAuth state
        self.oauth_states[state] = OAuthState(
            state=state,
            user_id=user_id,
            created_at=datetime.now()
        )
        
        # Build authorization URL
        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': ' '.join(YOUTUBE_SCOPES),
            'response_type': 'code',
            'access_type': 'offline',
            'prompt': 'consent',
            'state': state
        }
        
        auth_url = f"{YOUTUBE_OAUTH_URL}?{urllib.parse.urlencode(params)}"
        
        return {
            "auth_url": auth_url,
            "state": state,
            "user_id": user_id,
            "instructions": "Visit this URL to authorize YouTube access, then provide the authorization code"
        }
    
    async def exchange_code_for_tokens(self, code: str, state: str) -> Dict[str, Any]:
        """Exchange authorization code for access and refresh tokens"""
        if state not in self.oauth_states:
            return {"error": "Invalid or expired OAuth state"}
        
        oauth_state = self.oauth_states[state]
        user_id = oauth_state.user_id
        
        # Exchange code for tokens
        token_data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': self.redirect_uri
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(YOUTUBE_TOKEN_URL, data=token_data) as response:
                    if response.status == 200:
                        tokens = await response.json()
                        
                        # Calculate token expiration
                        expires_at = datetime.now() + timedelta(seconds=tokens.get('expires_in', 3600))
                        
                        # Store user tokens
                        self.user_tokens[user_id] = UserToken(
                            access_token=tokens['access_token'],
                            refresh_token=tokens.get('refresh_token', ''),
                            expires_at=expires_at,
                            user_id=user_id
                        )
                        
                        # Clean up OAuth state
                        del self.oauth_states[state]
                        
                        return {
                            "success": True,
                            "user_id": user_id,
                            "message": "Successfully authenticated with YouTube",
                            "expires_at": expires_at.isoformat()
                        }
                    else:
                        error_text = await response.text()
                        return {"error": f"Token exchange failed: {error_text}"}
            except Exception as e:
                return {"error": f"Token exchange error: {str(e)}"}
    
    async def refresh_access_token(self, user_id: str) -> Dict[str, Any]:
        """Refresh expired access token using refresh token"""
        if user_id not in self.user_tokens:
            return {"error": "No tokens found for user"}
        
        user_token = self.user_tokens[user_id]
        if not user_token.refresh_token:
            return {"error": "No refresh token available"}
        
        refresh_data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': user_token.refresh_token,
            'grant_type': 'refresh_token'
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(YOUTUBE_TOKEN_URL, data=refresh_data) as response:
                    if response.status == 200:
                        tokens = await response.json()
                        
                        # Update stored tokens
                        expires_at = datetime.now() + timedelta(seconds=tokens.get('expires_in', 3600))
                        self.user_tokens[user_id].access_token = tokens['access_token']
                        self.user_tokens[user_id].expires_at = expires_at
                        
                        return {
                            "success": True,
                            "message": "Token refreshed successfully",
                            "expires_at": expires_at.isoformat()
                        }
                    else:
                        error_text = await response.text()
                        return {"error": f"Token refresh failed: {error_text}"}
            except Exception as e:
                return {"error": f"Token refresh error: {str(e)}"}
    
    async def get_valid_token(self, user_id: str) -> Optional[str]:
        """Get a valid access token for the user, refreshing if necessary"""
        if user_id not in self.user_tokens:
            return None
        
        user_token = self.user_tokens[user_id]
        
        # Check if token is expired
        if datetime.now() >= user_token.expires_at:
            refresh_result = await self.refresh_access_token(user_id)
            if "error" in refresh_result:
                logger.error(f"Failed to refresh token for user {user_id}: {refresh_result['error']}")
                return None
        
        return self.user_tokens[user_id].access_token
    
    def is_user_authenticated(self, user_id: str) -> bool:
        """Check if user has valid authentication"""
        return user_id in self.user_tokens

class YouTubeService:
    """Service class for YouTube API interactions with OAuth support"""
    
    def __init__(self, api_key: Optional[str] = None, oauth_manager: Optional[YouTubeOAuthManager] = None):
        self.api_key = api_key
        self.oauth_manager = oauth_manager
        
    async def _get_headers(self, user_id: Optional[str] = None) -> Dict[str, str]:
        """Get appropriate headers for API request (OAuth or API key)"""
        headers = {'Content-Type': 'application/json'}
        
        if user_id and self.oauth_manager and self.oauth_manager.is_user_authenticated(user_id):
            # Use OAuth token
            access_token = await self.oauth_manager.get_valid_token(user_id)
            if access_token:
                headers['Authorization'] = f'Bearer {access_token}'
                return headers
        
        # Fallback to API key
        return headers
    
    async def _make_request(self, url: str, params: Dict[str, Any], user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Make authenticated request to YouTube API"""
        headers = await self._get_headers(user_id)
        
        # Add API key if no OAuth token
        if 'Authorization' not in headers and self.api_key:
            params['key'] = self.api_key
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, params=params, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('items', [])
                    else:
                        error_text = await response.text()
                        logger.error(f"YouTube API error {response.status}: {error_text}")
                        return []
            except Exception as e:
                logger.error(f"YouTube API request error: {e}")
                return []
        
    async def get_user_watch_history(self, user_id: str, max_results: int = 50) -> List[Dict[str, Any]]:
        """Get user's actual YouTube watch history using OAuth"""
        if not self.oauth_manager or not self.oauth_manager.is_user_authenticated(user_id):
            return []
        
        # Get watch history from YouTube API
        url = f"{YOUTUBE_BASE_URL}/activities"
        params = {
            'part': 'snippet,contentDetails',
            'mine': 'true',
            'maxResults': max_results
        }
        
        activities = await self._make_request(url, params, user_id)
        
        # Filter for watch activities and extract video data
        watch_history = []
        for activity in activities:
            if activity.get('snippet', {}).get('type') == 'upload':
                continue  # Skip uploads, we want watch history
            
            content_details = activity.get('contentDetails', {})
            if 'upload' in content_details:
                video_id = content_details['upload']['videoId']
                snippet = activity.get('snippet', {})
                
                watch_entry = {
                    "video_id": video_id,
                    "title": snippet.get('title', ''),
                    "channel_id": snippet.get('channelId', ''),
                    "channel_title": snippet.get('channelTitle', ''),
                    "watched_at": snippet.get('publishedAt', ''),
                    "activity_type": snippet.get('type', 'unknown')
                }
                watch_history.append(watch_entry)
        
        return watch_history
        
    async def get_video_details(self, video_ids: List[str], user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get detailed information about videos by their IDs"""
        if not video_ids:
            return []
            
        # YouTube API allows up to 50 video IDs per request
        video_chunks = [video_ids[i:i+50] for i in range(0, len(video_ids), 50)]
        all_videos = []
        
        for chunk in video_chunks:
            url = f"{YOUTUBE_BASE_URL}/videos"
            params = {
                'part': 'snippet,statistics,contentDetails',
                'id': ','.join(chunk)
            }
            
            videos = await self._make_request(url, params, user_id)
            all_videos.extend(videos)
                    
        return all_videos
    
    async def search_videos(self, query: str, max_results: int = 25, order: str = 'relevance', user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search for videos based on query with enhanced parameters"""
        url = f"{YOUTUBE_BASE_URL}/search"
        params = {
            'part': 'snippet',
            'q': query,
            'type': 'video',
            'maxResults': max_results,
            'order': order
        }
        
        return await self._make_request(url, params, user_id)
    
    async def get_trending_videos(self, region_code: str = 'US', category_id: str = '0', user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get trending videos for a specific region and category"""
        url = f"{YOUTUBE_BASE_URL}/videos"
        params = {
            'part': 'snippet,statistics',
            'chart': 'mostPopular',
            'regionCode': region_code,
            'categoryId': category_id,
            'maxResults': 50
        }
        
        return await self._make_request(url, params, user_id)

    async def get_channel_info(self, channel_ids: List[str], user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get information about channels"""
        if not channel_ids:
            return []
            
        url = f"{YOUTUBE_BASE_URL}/channels"
        params = {
            'part': 'snippet,statistics',
            'id': ','.join(channel_ids)
        }
        
        return await self._make_request(url, params, user_id)

    async def enrich_watch_history(self, watch_history: List[Dict[str, Any]], user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Enrich watch history with additional metadata from YouTube API"""
        if not watch_history:
            return []
        
        # Extract video IDs from watch history
        video_ids = [video.get('video_id') for video in watch_history if video.get('video_id')]
        
        # Get detailed video information
        video_details = {}
        if video_ids:
            details = await self.get_video_details(video_ids, user_id)
            for video in details:
                video_details[video['id']] = video
        
        # Enrich each watch history entry
        enriched_history = []
        for entry in watch_history:
            video_id = entry.get('video_id')
            enriched_entry = dict(entry)  # Copy original data
            
            if video_id and video_id in video_details:
                video_detail = video_details[video_id]
                enriched_entry.update({
                    'video_metadata': {
                        'description': video_detail['snippet'].get('description', ''),
                        'tags': video_detail['snippet'].get('tags', []),
                        'category_id': video_detail['snippet'].get('categoryId'),
                        'published_at': video_detail['snippet'].get('publishedAt'),
                        'thumbnail': video_detail['snippet'].get('thumbnails', {}).get('medium', {}).get('url'),
                        'view_count': video_detail.get('statistics', {}).get('viewCount'),
                        'like_count': video_detail.get('statistics', {}).get('likeCount'),
                        'comment_count': video_detail.get('statistics', {}).get('commentCount'),
                        'duration': video_detail.get('contentDetails', {}).get('duration')
                    }
                })
            
            enriched_history.append(enriched_entry)
        
        return enriched_history

# Initialize services
oauth_manager = YouTubeOAuthManager(
    YOUTUBE_CLIENT_ID, 
    YOUTUBE_CLIENT_SECRET, 
    YOUTUBE_REDIRECT_URI
) if YOUTUBE_CLIENT_ID and YOUTUBE_CLIENT_SECRET else None

youtube_service = YouTubeService(
    api_key=YOUTUBE_API_KEY,
    oauth_manager=oauth_manager
)

@mcp.resource("watch-history://user/{user_id}")
async def get_watch_history(user_id: str) -> Dict[str, Any]:
    """
    Get comprehensive watch history for a specific user.
    Uses real YouTube data if user is authenticated via OAuth, otherwise returns mock data.
    """
    if oauth_manager and oauth_manager.is_user_authenticated(user_id):
        # Get real watch history from YouTube API
        try:
            real_history = await youtube_service.get_user_watch_history(user_id, max_results=50)
            return {
                "user_id": user_id,
                "total_videos": len(real_history),
                "history": real_history,
                "last_updated": datetime.now().isoformat(),
                "metadata": {
                    "data_source": "youtube_api_oauth",
                    "includes_interactions": False,  # YouTube API doesn't provide detailed interaction data
                    "includes_watch_duration": False,
                    "includes_tags": False,
                    "authenticated": True
                }
            }
        except Exception as e:
            logger.error(f"Error fetching real watch history for {user_id}: {e}")
    
    # Fallback to mock implementation
    mock_history = [
        {
            "video_id": "dQw4w9WgXcQ",
            "title": "Rick Astley - Never Gonna Give You Up",
            "channel_id": "UCuAXFkgsw1L7xaCfnd5JJOw",
            "channel_title": "Rick Astley",
            "watched_at": "2024-10-01T10:30:00Z",
            "duration_seconds": 212,
            "category": "Music",
            "watch_duration_seconds": 212,  # How long user actually watched
            "watch_percentage": 100,  # Percentage of video watched
            "interaction": "liked",  # liked, disliked, commented, shared, none
            "tags": ["80s", "pop", "classic", "music video", "dance"]
        },
        {
            "video_id": "9bZkp7q19f0",
            "title": "PSY - GANGNAM STYLE",
            "channel_id": "UC2pmfLm7iq6Ov1UwYrWYkZA",
            "channel_title": "officialpsy",
            "watched_at": "2024-10-02T15:45:00Z",
            "duration_seconds": 253,
            "category": "Music",
            "watch_duration_seconds": 180,
            "watch_percentage": 71,
            "interaction": "shared",
            "tags": ["k-pop", "korean", "dance", "viral", "music video"]
        },
        {
            "video_id": "kffacxfA7G4",
            "title": "Baby Shark Dance",
            "channel_id": "UCGwA6bCwpRJOEuJ3Fv3aJgA",
            "channel_title": "Pinkfong Baby Shark",
            "watched_at": "2024-10-03T09:15:00Z",
            "duration_seconds": 137,
            "category": "Entertainment",
            "watch_duration_seconds": 50,
            "watch_percentage": 36,
            "interaction": "none",
            "tags": ["kids", "children", "nursery rhyme", "educational", "family"]
        }
    ]
    
    return {
        "user_id": user_id,
        "total_videos": len(mock_history),
        "history": mock_history,
        "last_updated": datetime.now().isoformat(),
        "metadata": {
            "data_source": "mock_implementation",
            "includes_interactions": True,
            "includes_watch_duration": True,
            "includes_tags": True,
            "authenticated": False,
            "note": "This is mock data. Connect with OAuth to get real YouTube data."
        }
    }

@mcp.resource("user-profile://user/{user_id}")
async def get_user_profile(user_id: str) -> Dict[str, Any]:
    """Get user profile information for context in analysis"""
    # Mock user profile data
    return {
        "user_id": user_id,
        "profile": {
            "age_range": "25-34",
            "primary_language": "en",
            "region": "US",
            "timezone": "America/New_York",
            "device_types": ["mobile", "desktop", "tv"],
            "subscription_status": "premium"
        },
        "preferences": {
            "auto_play": True,
            "notifications": True,
            "quality_preference": "1080p",
            "captions": False
        },
        "generated_at": datetime.now().isoformat()
    }

@mcp.tool()
async def start_youtube_oauth(user_id: str) -> Dict[str, Any]:
    """
    Start YouTube OAuth flow for a user to authenticate and access their real YouTube data.
    
    Args:
        user_id: Unique identifier for the user
    
    Returns:
        Dictionary containing OAuth authorization URL and instructions
    """
    if not oauth_manager:
        return {
            "error": "OAuth not configured. Please set YOUTUBE_CLIENT_ID and YOUTUBE_CLIENT_SECRET environment variables."
        }
    
    try:
        auth_data = oauth_manager.generate_auth_url(user_id)
        return {
            "success": True,
            "user_id": user_id,
            **auth_data,
            "next_steps": [
                "1. Visit the provided auth_url in your browser",
                "2. Sign in to your YouTube/Google account",
                "3. Grant permissions to access your YouTube data",
                "4. Copy the authorization code from the callback",
                "5. Use complete_youtube_oauth tool with the code"
            ]
        }
    except Exception as e:
        return {
            "error": f"Failed to start OAuth flow: {str(e)}",
            "user_id": user_id
        }

@mcp.tool()
async def complete_youtube_oauth(authorization_code: str, state: str) -> Dict[str, Any]:
    """
    Complete YouTube OAuth flow by exchanging authorization code for access tokens.
    
    Args:
        authorization_code: The authorization code received from YouTube OAuth callback
        state: The state parameter from the OAuth flow
    
    Returns:
        Dictionary containing OAuth completion status and user information
    """
    if not oauth_manager:
        return {
            "error": "OAuth not configured. Please set YOUTUBE_CLIENT_ID and YOUTUBE_CLIENT_SECRET environment variables."
        }
    
    try:
        result = await oauth_manager.exchange_code_for_tokens(authorization_code, state)
        if "success" in result:
            return {
                **result,
                "next_steps": [
                    "OAuth authentication completed successfully",
                    "You can now access real YouTube data using other tools",
                    "Your watch history and other YouTube data will be fetched from the API"
                ]
            }
        else:
            return result
    except Exception as e:
        return {
            "error": f"Failed to complete OAuth flow: {str(e)}"
        }

@mcp.tool()
async def check_youtube_auth_status(user_id: str) -> Dict[str, Any]:
    """
    Check if a user is authenticated with YouTube OAuth.
    
    Args:
        user_id: The user ID to check authentication status for
    
    Returns:
        Dictionary containing authentication status and available features
    """
    if not oauth_manager:
        return {
            "user_id": user_id,
            "authenticated": False,
            "reason": "OAuth not configured on server",
            "available_features": ["mock_data_only"],
            "oauth_configured": False
        }
    
    is_authenticated = oauth_manager.is_user_authenticated(user_id)
    
    return {
        "user_id": user_id,
        "authenticated": is_authenticated,
        "oauth_configured": True,
        "available_features": [
            "real_watch_history",
            "personalized_search",
            "user_playlists",
            "subscription_data"
        ] if is_authenticated else [
            "mock_data_only",
            "public_search",
            "trending_videos"
        ],
        "message": "User can access real YouTube data" if is_authenticated else "User needs to authenticate to access real YouTube data"
    }

@mcp.tool()
async def get_enriched_watch_history(user_id: str, include_metadata: bool = True) -> Dict[str, Any]:
    """
    Get user's watch history enriched with comprehensive video metadata for LLM analysis.
    
    Args:
        user_id: The user ID to get watch history for
        include_metadata: Whether to include detailed video metadata from YouTube API
    
    Returns:
        Dictionary containing enriched watch history data for LLM analysis
    """
    if not youtube_service:
        return {
            "error": "YouTube service not configured.",
            "user_id": user_id,
            "history": []
        }
    
    try:
        # Get basic watch history (real or mock depending on auth status)
        history_data = await get_watch_history(user_id)
        watch_history = history_data.get('history', [])
        
        # Enrich with YouTube API metadata if requested
        if include_metadata and watch_history:
            enriched_history = await youtube_service.enrich_watch_history(watch_history, user_id)
        else:
            enriched_history = watch_history
        
        return {
            "user_id": user_id,
            "total_videos": len(enriched_history),
            "enriched_history": enriched_history,
            "metadata": {
                "api_enriched": include_metadata,
                "data_ready_for_analysis": True,
                "data_source": history_data.get('metadata', {}).get('data_source', 'unknown'),
                "authenticated": history_data.get('metadata', {}).get('authenticated', False),
                "suggested_analysis_approaches": [
                    "Analyze viewing patterns by time of day",
                    "Identify content preferences by category and tags",
                    "Evaluate engagement through watch percentages",
                    "Discover channel loyalty patterns",
                    "Understand content discovery sources"
                ]
            },
            "generated_at": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting enriched watch history: {e}")
        return {
            "error": f"Failed to get enriched watch history: {str(e)}",
            "user_id": user_id,
            "history": []
        }

@mcp.tool()
async def search_videos_advanced(
    query: str, 
    max_results: int = 25, 
    order: str = 'relevance',
    published_after: Optional[str] = None,
    duration: Optional[str] = None,
    user_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Advanced video search with multiple parameters for comprehensive data gathering.
    
    Args:
        query: Search query string
        max_results: Maximum number of results to return
        order: Sort order (relevance, date, rating, viewCount, title)
        published_after: ISO date string to filter videos published after this date
        duration: Video duration filter (short, medium, long)
        user_id: Optional user ID for personalized search (if authenticated)
    
    Returns:
        Dictionary containing search results with metadata for LLM analysis
    """
    if not youtube_service:
        return {
            "error": "YouTube service not configured",
            "query": query,
            "results": []
        }
    
    try:
        search_results = await youtube_service.search_videos(query, max_results, order, user_id)
        
        return {
            "query": query,
            "search_parameters": {
                "max_results": max_results,
                "order": order,
                "published_after": published_after,
                "duration": duration,
                "personalized": user_id is not None and oauth_manager and oauth_manager.is_user_authenticated(user_id)
            },
            "total_results": len(search_results),
            "results": search_results,
            "analysis_suggestions": [
                "Analyze content themes and topics",
                "Evaluate creator diversity",
                "Assess content freshness and trends",
                "Compare engagement metrics"
            ],
            "generated_at": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error in advanced video search: {e}")
        return {
            "error": f"Search failed: {str(e)}",
            "query": query,
            "results": []
        }

@mcp.tool()
async def get_video_context(video_id: str, include_similar: bool = True, user_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Get comprehensive context about a specific video including details and similar content.
    
    Args:
        video_id: The YouTube video ID to analyze
        include_similar: Whether to include similar videos in the response
        user_id: Optional user ID for personalized similar video recommendations
    
    Returns:
        Dictionary containing detailed video context for LLM analysis
    """
    if not youtube_service:
        return {
            "error": "YouTube service not configured",
            "video_id": video_id,
            "context": {}
        }
    
    try:
        # Get detailed video information
        video_details = await youtube_service.get_video_details([video_id], user_id)
        if not video_details:
            return {
                "error": f"Video {video_id} not found",
                "video_id": video_id,
                "context": {}
            }
        
        video = video_details[0]
        context = {
            "video_details": video,
            "channel_id": video['snippet']['channelId'],
            "category_id": video['snippet'].get('categoryId'),
            "tags": video['snippet'].get('tags', []),
            "description": video['snippet'].get('description', ''),
            "statistics": video.get('statistics', {}),
            "content_details": video.get('contentDetails', {})
        }
        
        # Get channel information
        channel_info = await youtube_service.get_channel_info([video['snippet']['channelId']], user_id)
        if channel_info:
            context["channel_details"] = channel_info[0]
        
        # Get similar videos if requested
        if include_similar:
            video_title = video['snippet']['title']
            channel_title = video['snippet']['channelTitle']
            search_query = f"{video_title} {channel_title}"
            similar_videos = await youtube_service.search_videos(search_query, max_results=10, user_id=user_id)
            
            # Filter out the original video
            similar_videos = [
                v for v in similar_videos 
                if v.get('id', {}).get('videoId') != video_id
            ]
            context["similar_videos"] = similar_videos
        
        return {
            "video_id": video_id,
            "context": context,
            "personalized": user_id is not None and oauth_manager and oauth_manager.is_user_authenticated(user_id),
            "analysis_opportunities": [
                "Content theme and topic analysis",
                "Audience engagement patterns",
                "Channel authority and expertise",
                "Content freshness and relevance",
                "Similar content landscape"
            ],
            "generated_at": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting video context: {e}")
        return {
            "error": f"Failed to get video context: {str(e)}",
            "video_id": video_id,
            "context": {}
        }

@mcp.tool()
async def get_trending_by_category(category: str = "Entertainment", region: str = "US", user_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Get trending videos by category and region with comprehensive metadata.
    
    Args:
        category: Video category (Entertainment, Music, Gaming, etc.)
        region: Country code (US, GB, CA, etc.)
        user_id: Optional user ID for authenticated requests
    
    Returns:
        Dictionary containing trending videos with analysis metadata
    """
    if not youtube_service:
        return {
            "error": "YouTube service not configured",
            "category": category,
            "trending_videos": []
        }
    
    try:
        # Category mapping (simplified)
        category_ids = {
            "Music": "10",
            "Gaming": "20",
            "Entertainment": "24",
            "Sports": "17",
            "Technology": "28",
            "Education": "27",
            "News": "25"
        }
        
        category_id = category_ids.get(category, "0")  # 0 = all categories
        trending_videos = await youtube_service.get_trending_videos(region, category_id, user_id)
        
        return {
            "category": category,
            "region": region,
            "category_id": category_id,
            "trending_videos": trending_videos,
            "total_found": len(trending_videos),
            "personalized": user_id is not None and oauth_manager and oauth_manager.is_user_authenticated(user_id),
            "analysis_metadata": {
                "trend_indicators": ["view_count", "like_ratio", "comment_activity"],
                "regional_context": region,
                "category_context": category,
                "data_freshness": "real_time"
            },
            "suggested_analysis": [
                "Identify trending content themes",
                "Analyze viral content patterns",
                "Compare regional preferences",
                "Understand category-specific trends"
            ],
            "generated_at": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting trending videos: {e}")
        return {
            "error": f"Failed to get trending videos: {str(e)}",
            "category": category,
            "trending_videos": []
        }

@mcp.tool()
async def get_channel_analytics_data(channel_ids: List[str], user_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Get comprehensive channel data for analysis.
    
    Args:
        channel_ids: List of YouTube channel IDs to analyze
        user_id: Optional user ID for authenticated requests
    
    Returns:
        Dictionary containing detailed channel information for LLM analysis
    """
    if not youtube_service:
        return {
            "error": "YouTube service not configured",
            "channel_data": []
        }
    
    try:
        channel_data = await youtube_service.get_channel_info(channel_ids, user_id)
        
        return {
            "total_channels": len(channel_data),
            "channel_data": channel_data,
            "personalized": user_id is not None and oauth_manager and oauth_manager.is_user_authenticated(user_id),
            "analysis_dimensions": [
                "Subscriber growth patterns",
                "Content publishing frequency",
                "Audience engagement rates",
                "Channel authority indicators",
                "Cross-channel collaboration opportunities"
            ],
            "generated_at": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting channel analytics data: {e}")
        return {
            "error": f"Failed to get channel data: {str(e)}",
            "channel_data": []
        }

if __name__ == "__main__":
    missing_config = []
    
    if not YOUTUBE_API_KEY:
        missing_config.append("YOUTUBE_API_KEY")
    
    if not YOUTUBE_CLIENT_ID:
        missing_config.append("YOUTUBE_CLIENT_ID")
        
    if not YOUTUBE_CLIENT_SECRET:
        missing_config.append("YOUTUBE_CLIENT_SECRET")
    
    if missing_config:
        logger.warning(f"Missing configuration: {', '.join(missing_config)}")
        logger.warning("OAuth features will be disabled. Set these environment variables for full functionality.")
    else:
        logger.info("YouTube OAuth is fully configured and ready")
    
    # Run the MCP server
    mcp.run()