from fastmcp import FastMCP # fastMCP 2.0
from dotenv import load_dotenv
import os
import aiohttp
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging
import base64
import secrets
import urllib.parse
import json
import asyncio
from dataclasses import dataclass
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

mcp = FastMCP(
    name="YouTube Data Provider"
)

# YouTube Data API configuration
YOUTUBE_API_KEY = os.getenv('YOUTUBE_API_KEY')
YOUTUBE_CLIENT_ID = os.getenv('YOUTUBE_CLIENT_ID')
YOUTUBE_CLIENT_SECRET = os.getenv('YOUTUBE_CLIENT_SECRET')
YOUTUBE_REDIRECT_URI = os.getenv('YOUTUBE_REDIRECT_URI', 'http://localhost:8080/oauth/callback')
YOUTUBE_BASE_URL = "https://www.googleapis.com/youtube/v3"
YOUTUBE_OAUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
YOUTUBE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# File paths for persistent storage
AUTH_DATA_FILE = Path("youtube_auth.json")
SESSION_FILE = Path("youtube_session.json")

# YouTube API scopes for accessing user data
YOUTUBE_SCOPES = [
    "https://www.googleapis.com/auth/youtube.readonly",
    "https://www.googleapis.com/auth/youtube"
]

@dataclass
class UserSession:
    """Represents current user session"""
    access_token: str
    refresh_token: str
    expires_at: datetime
    user_info: Dict[str, Any]
    authenticated_at: datetime

class SingleUserAuthManager:
    """Simplified authentication manager for single user experience"""
    
    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.current_session: Optional[UserSession] = None
        self.auth_state: Optional[str] = None
        self.callback_server = None
        self.load_session()
    
    def save_session(self):
        """Save current session to file"""
        if self.current_session:
            session_data = {
                'access_token': self.current_session.access_token,
                'refresh_token': self.current_session.refresh_token,
                'expires_at': self.current_session.expires_at.isoformat(),
                'user_info': self.current_session.user_info,
                'authenticated_at': self.current_session.authenticated_at.isoformat()
            }
            with open(AUTH_DATA_FILE, 'w') as f:
                json.dump(session_data, f, indent=2)
    
    def load_session(self):
        """Load session from file if exists"""
        try:
            if AUTH_DATA_FILE.exists():
                with open(AUTH_DATA_FILE, 'r') as f:
                    session_data = json.load(f)
                
                self.current_session = UserSession(
                    access_token=session_data['access_token'],
                    refresh_token=session_data['refresh_token'],
                    expires_at=datetime.fromisoformat(session_data['expires_at']),
                    user_info=session_data['user_info'],
                    authenticated_at=datetime.fromisoformat(session_data['authenticated_at'])
                )
                logger.info("Loaded existing authentication session")
        except Exception as e:
            logger.info(f"No existing session found: {e}")
            self.current_session = None
    
    async def start_interactive_auth(self) -> Dict[str, Any]:
        """Start interactive authentication with automatic callback handling"""
        import webbrowser
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import threading
        import urllib.parse
        
        self.auth_state = secrets.token_urlsafe(32)
        auth_result = {'completed': False, 'error': None, 'code': None}
        
        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(handler_self):
                try:
                    logger.info(f"Received callback request: {handler_self.path}")
                    parsed_url = urllib.parse.urlparse(handler_self.path)
                    
                    # Ignore favicon.ico and other non-OAuth requests
                    if parsed_url.path in ['/favicon.ico', '/']:
                        handler_self.send_response(404)
                        handler_self.end_headers()
                        return
                    
                    # Only process OAuth callback
                    if parsed_url.path != '/oauth/callback':
                        handler_self.send_response(404)
                        handler_self.end_headers()
                        return
                    
                    query_params = urllib.parse.parse_qs(parsed_url.query)
                    logger.info(f"OAuth callback query params: {query_params}")
                    
                    if 'error' in query_params:
                        auth_result['error'] = f"OAuth error: {query_params['error'][0]}"
                        logger.error(f"OAuth error: {query_params['error'][0]}")
                    elif 'code' in query_params and 'state' in query_params:
                        received_state = query_params['state'][0]
                        if received_state == self.auth_state:
                            auth_result['code'] = query_params['code'][0]
                            auth_result['completed'] = True
                            logger.info("✅ Successfully received authorization code")
                            
                            # Send success response
                            handler_self.send_response(200)
                            handler_self.send_header('Content-type', 'text/html')
                            handler_self.end_headers()
                            success_html = '''
                            <html><head><title>Authentication Successful</title></head><body>
                                <h2>✓ Authentication Successful!</h2>
                                <p>You can now close this tab and return to your chat.</p>
                                <script>setTimeout(() => window.close(), 3000);</script>
                            </body></html>
                            '''.encode('utf-8')
                            handler_self.wfile.write(success_html)
                            return  # Don't process further
                        else:
                            auth_result['error'] = 'Invalid state parameter - possible CSRF attack'
                            logger.error("❌ State parameter mismatch")
                    else:
                        auth_result['error'] = 'Missing authorization code or state parameter'
                        logger.error(f"❌ Missing required parameters in OAuth callback. Received: {list(query_params.keys())}")
                        
                    # Send error response if there was an error
                    if auth_result['error'] and not auth_result['completed']:
                        handler_self.send_response(400)
                        handler_self.send_header('Content-type', 'text/html')
                        handler_self.end_headers()
                        error_html = f'''
                        <html><head><title>Authentication Failed</title></head><body>
                            <h2>X Authentication Failed</h2>
                            <p>Error: {auth_result['error']}</p>
                        </body></html>
                        '''.encode('utf-8')
                        handler_self.wfile.write(error_html)
                        
                except Exception as e:
                    auth_result['error'] = f"Callback handler error: {str(e)}"
                    logger.error(f"Exception in callback handler: {e}")
            
            def log_message(self, format, *args):
                # Re-enable logging for debugging
                logger.info(f"HTTP Server: {format % args}")
        
        # Start callback server with port fallback
        server = None
        server_port = 8080
        max_port_attempts = 5
        
        for attempt in range(max_port_attempts):
            try:
                server = HTTPServer(('localhost', server_port), CallbackHandler)
                break
            except OSError as e:
                if "Address already in use" in str(e) and attempt < max_port_attempts - 1:
                    server_port += 1
                    logger.info(f"Port {server_port - 1} in use, trying port {server_port}")
                    continue
                else:
                    return {'error': f'Cannot start callback server: {str(e)}'}
        
        if not server:
            return {'error': 'Could not find an available port for callback server'}
        
        # Update redirect URI to match the actual port used
        actual_redirect_uri = f"http://localhost:{server_port}/oauth/callback"
        
        try:
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            # Give server time to start
            await asyncio.sleep(0.5)
            
            logger.info(f"Callback server started on port {server_port}")
            
            # Build authorization URL with actual redirect URI
            params = {
                'client_id': self.client_id,
                'redirect_uri': actual_redirect_uri,
                'scope': ' '.join(YOUTUBE_SCOPES),
                'response_type': 'code',
                'access_type': 'offline',
                'prompt': 'consent',
                'state': self.auth_state
            }
            
            auth_url = f"{YOUTUBE_OAUTH_URL}?{urllib.parse.urlencode(params)}"
            
            # Open browser automatically
            webbrowser.open(auth_url)
            
            # Wait for callback
            for _ in range(120):  # Wait up to 2 minutes
                if auth_result['completed'] or auth_result['error']:
                    break
                await asyncio.sleep(1)
            
            server.shutdown()
            
            if auth_result['error']:
                return {'error': auth_result['error']}
            
            if not auth_result['completed']:
                return {'error': 'Authentication timeout. Please try again.'}
            
            # Exchange code for tokens
            logger.info(f"Starting token exchange for code: {auth_result['code'][:20]}...")
            token_result = await self.exchange_code_for_tokens(auth_result['code'], actual_redirect_uri)
            if 'error' in token_result:
                logger.error(f"Token exchange failed: {token_result['error']}")
                return token_result
            
            logger.info("Token exchange completed successfully")
            
            return {
                'success': True,
                'message': 'Successfully authenticated with YouTube!',
                'user_info': self.current_session.user_info if self.current_session else {}
            }
            
        except Exception as e:
            return {'error': f'Authentication failed: {str(e)}'}
    
    async def exchange_code_for_tokens(self, code: str, redirect_uri: str = None) -> Dict[str, Any]:
        """Exchange authorization code for access tokens"""
        # Use the same redirect URI that was used in the auth request
        actual_redirect_uri = redirect_uri or self.redirect_uri
        
        token_data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': actual_redirect_uri
        }
        
        logger.info(f"Exchanging code for tokens with redirect_uri: {actual_redirect_uri}")
        
        async with aiohttp.ClientSession() as session:
            try:
                logger.info(f"Making token exchange request to: {YOUTUBE_TOKEN_URL}")
                async with session.post(YOUTUBE_TOKEN_URL, data=token_data) as response:
                    response_text = await response.text()
                    logger.info(f"Token exchange response status: {response.status}")
                    
                    if response.status == 200:
                        tokens = await response.json()
                        logger.info("Successfully received tokens from Google")
                        
                        # Get user info
                        user_info = await self.get_user_info(tokens['access_token'])
                        
                        # Calculate token expiration
                        expires_at = datetime.now() + timedelta(seconds=tokens.get('expires_in', 3600))
                        
                        # Create session
                        self.current_session = UserSession(
                            access_token=tokens['access_token'],
                            refresh_token=tokens.get('refresh_token', ''),
                            expires_at=expires_at,
                            user_info=user_info,
                            authenticated_at=datetime.now()
                        )
                        
                        # Save session
                        self.save_session()
                        logger.info("Session saved successfully")
                        
                        return {
                            'success': True,
                            'message': 'Authentication completed successfully',
                            'user_info': user_info
                        }
                    else:
                        logger.error(f"Token exchange failed with status {response.status}: {response_text}")
                        return {'error': f'Token exchange failed: HTTP {response.status} - {response_text}'}
            except Exception as e:
                logger.error(f"Exception during token exchange: {e}")
                return {'error': f'Token exchange error: {str(e)}'}
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get basic user information from YouTube API"""
        headers = {'Authorization': f'Bearer {access_token}'}
        
        async with aiohttp.ClientSession() as session:
            try:
                # Get channel info for current user
                async with session.get(
                    f"{YOUTUBE_BASE_URL}/channels?part=snippet&mine=true", 
                    headers=headers
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data.get('items'):
                            channel = data['items'][0]['snippet']
                            return {
                                'channel_id': data['items'][0]['id'],
                                'channel_title': channel.get('title', 'Unknown'),
                                'channel_description': channel.get('description', ''),
                                'thumbnail': channel.get('thumbnails', {}).get('default', {}).get('url')
                            }
                
                return {'channel_title': 'YouTube User'}
            except Exception as e:
                logger.error(f"Error getting user info: {e}")
                return {'channel_title': 'YouTube User'}
    
    async def refresh_access_token(self) -> Dict[str, Any]:
        """Refresh expired access token using refresh token"""
        if not self.current_session or not self.current_session.refresh_token:
            return {'error': 'No refresh token available'}
        
        refresh_data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': self.current_session.refresh_token,
            'grant_type': 'refresh_token'
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(YOUTUBE_TOKEN_URL, data=refresh_data) as response:
                    if response.status == 200:
                        tokens = await response.json()
                        
                        # Update session
                        expires_at = datetime.now() + timedelta(seconds=tokens.get('expires_in', 3600))
                        self.current_session.access_token = tokens['access_token']
                        self.current_session.expires_at = expires_at
                        
                        # Save updated session
                        self.save_session()
                        
                        return {'success': True, 'message': 'Token refreshed successfully'}
                    else:
                        error_text = await response.text()
                        return {'error': f'Token refresh failed: {error_text}'}
            except Exception as e:
                return {'error': f'Token refresh error: {str(e)}'}
    
    async def get_valid_token(self) -> Optional[str]:
        """Get a valid access token, refreshing if necessary"""
        if not self.current_session:
            return None
        
        # Check if token is expired
        if datetime.now() >= self.current_session.expires_at:
            refresh_result = await self.refresh_access_token()
            if 'error' in refresh_result:
                logger.error(f"Failed to refresh token: {refresh_result['error']}")
                return None
        
        return self.current_session.access_token
    
    def is_authenticated(self) -> bool:
        """Check if user has valid authentication"""
        return self.current_session is not None
    
    def logout(self):
        """Clear current session and logout user"""
        self.current_session = None
        if AUTH_DATA_FILE.exists():
            AUTH_DATA_FILE.unlink()
        logger.info("User logged out successfully")

class YouTubeService:
    """Service class for YouTube API interactions with simplified authentication"""
    
    def __init__(self, api_key: Optional[str] = None, auth_manager: Optional[SingleUserAuthManager] = None):
        self.api_key = api_key
        self.auth_manager = auth_manager
        
    async def _get_headers(self) -> Dict[str, str]:
        """Get appropriate headers for API request (OAuth or API key)"""
        headers = {'Content-Type': 'application/json'}
        
        if self.auth_manager and self.auth_manager.is_authenticated():
            # Use OAuth token
            access_token = await self.auth_manager.get_valid_token()
            if access_token:
                headers['Authorization'] = f'Bearer {access_token}'
                return headers
        
        # Fallback to API key
        return headers
    
    async def _make_request(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Make authenticated request to YouTube API"""
        headers = await self._get_headers()
        
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
        
    async def get_user_watch_history(self, max_results: int = 50) -> List[Dict[str, Any]]:
        """
        NOTE: YouTube API does not provide access to user's watch history due to privacy policies.
        This method returns user's uploaded videos and channel activities instead.
        For actual watch history, users would need to use Google Takeout.
        """
        if not self.auth_manager or not self.auth_manager.is_authenticated():
            return []
        
        # Get user's channel activities (uploads, likes, etc.) instead of watch history
        url = f"{YOUTUBE_BASE_URL}/activities"
        params = {
            'part': 'snippet,contentDetails',
            'mine': 'true',
            'maxResults': max_results
        }
        
        activities = await self._make_request(url, params)
        
        # Process activities to extract meaningful data
        activity_history = []
        for activity in activities:
            snippet = activity.get('snippet', {})
            content_details = activity.get('contentDetails', {})
            
            # Handle different activity types
            activity_entry = {
                "activity_id": activity.get('id', ''),
                "type": snippet.get('type', ''),
                "title": snippet.get('title', ''),
                "description": snippet.get('description', ''),
                "channel_id": snippet.get('channelId', ''),
                "channel_title": snippet.get('channelTitle', ''),
                "published_at": snippet.get('publishedAt', ''),
                "thumbnails": snippet.get('thumbnails', {}),
                "content_details": content_details
            }
            
            # Add video ID if it's a video-related activity
            if 'upload' in content_details:
                activity_entry['video_id'] = content_details['upload']['videoId']
            elif 'like' in content_details:
                activity_entry['video_id'] = content_details['like']['resourceId']['videoId']
            elif 'favorite' in content_details:
                activity_entry['video_id'] = content_details['favorite']['resourceId']['videoId']
            
            activity_history.append(activity_entry)
        
        return activity_history
        
    async def get_video_details(self, video_ids: List[str]) -> List[Dict[str, Any]]:
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
            
            videos = await self._make_request(url, params)
            all_videos.extend(videos)
                    
        return all_videos
    
    async def search_videos(self, query: str, max_results: int = 25, order: str = 'relevance') -> List[Dict[str, Any]]:
        """Search for videos based on query with enhanced parameters"""
        url = f"{YOUTUBE_BASE_URL}/search"
        params = {
            'part': 'snippet',
            'q': query,
            'type': 'video',
            'maxResults': max_results,
            'order': order
        }
        
        return await self._make_request(url, params)
    
    async def get_trending_videos(self, region_code: str = 'US', category_id: str = '0') -> List[Dict[str, Any]]:
        """Get trending videos for a specific region and category"""
        url = f"{YOUTUBE_BASE_URL}/videos"
        params = {
            'part': 'snippet,statistics',
            'chart': 'mostPopular',
            'regionCode': region_code,
            'categoryId': category_id,
            'maxResults': 50
        }
        
        return await self._make_request(url, params)

    async def get_channel_info(self, channel_ids: List[str]) -> List[Dict[str, Any]]:
        """Get information about channels"""
        if not channel_ids:
            return []
            
        url = f"{YOUTUBE_BASE_URL}/channels"
        params = {
            'part': 'snippet,statistics',
            'id': ','.join(channel_ids)
        }
        
        return await self._make_request(url, params)

    async def enrich_watch_history(self, watch_history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich watch history with additional metadata from YouTube API"""
        if not watch_history:
            return []
        
        # Extract video IDs from watch history
        video_ids = [video.get('video_id') for video in watch_history if video.get('video_id')]
        
        # Get detailed video information
        video_details = {}
        if video_ids:
            details = await self.get_video_details(video_ids)
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
auth_manager = SingleUserAuthManager(
    YOUTUBE_CLIENT_ID, 
    YOUTUBE_CLIENT_SECRET, 
    YOUTUBE_REDIRECT_URI
) if YOUTUBE_CLIENT_ID and YOUTUBE_CLIENT_SECRET else None

youtube_service = YouTubeService(
    api_key=YOUTUBE_API_KEY,
    auth_manager=auth_manager
)

@mcp.resource("watch-history://current-user")
async def get_watch_history() -> Dict[str, Any]:
    """
    Get comprehensive watch history for the current authenticated user.
    Uses real YouTube data if user is authenticated via OAuth, otherwise returns mock data.
    """
    if auth_manager and auth_manager.is_authenticated():
        # Get real watch history from YouTube API
        try:
            real_history = await youtube_service.get_user_watch_history(max_results=50)
            return {
                "total_videos": len(real_history),
                "history": real_history,
                "last_updated": datetime.now().isoformat(),
                "user_info": auth_manager.current_session.user_info if auth_manager.current_session else {},
                "metadata": {
                    "data_source": "youtube_api_oauth",
                    "includes_interactions": False,  # YouTube API doesn't provide detailed interaction data
                    "includes_watch_duration": False,
                    "includes_tags": False,
                    "authenticated": True
                }
            }
        except Exception as e:
            logger.error(f"Error fetching real watch history: {e}")
    
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
        "total_videos": len(mock_history),
        "history": mock_history,
        "last_updated": datetime.now().isoformat(),
        "metadata": {
            "data_source": "mock_implementation",
            "includes_interactions": True,
            "includes_watch_duration": True,
            "includes_tags": True,
            "authenticated": False,
            "note": "This is mock data. Use 'login_to_youtube' tool to get real YouTube data."
        }
    }

@mcp.resource("user-profile://current-user")
async def get_user_profile() -> Dict[str, Any]:
    """Get current user profile information"""
    if auth_manager and auth_manager.is_authenticated():
        user_info = auth_manager.current_session.user_info
        return {
            "authenticated": True,
            "youtube_profile": user_info,
            "session_info": {
                "authenticated_at": auth_manager.current_session.authenticated_at.isoformat(),
                "expires_at": auth_manager.current_session.expires_at.isoformat()
            },
            "generated_at": datetime.now().isoformat()
        }
    
    # Mock user profile data
    return {
        "authenticated": False,
        "note": "Use 'login_to_youtube' tool to authenticate and get real profile data",
        "generated_at": datetime.now().isoformat()
    }

@mcp.tool()
async def login_to_youtube() -> Dict[str, Any]:
    """
    Start interactive YouTube authentication. Opens browser automatically for seamless login.
    
    Returns:
        Dictionary containing authentication status and user information
    """
    if not auth_manager:
        return {
            "error": "Authentication not configured. Please set YOUTUBE_CLIENT_ID and YOUTUBE_CLIENT_SECRET environment variables."
        }
    
    if auth_manager.is_authenticated():
        return {
            "success": True,
            "message": "Already authenticated with YouTube",
            "user_info": auth_manager.current_session.user_info
        }
    
    try:
        result = await auth_manager.start_interactive_auth()
        return result
    except Exception as e:
        return {
            "error": f"Failed to authenticate: {str(e)}"
        }

@mcp.tool()
async def logout_from_youtube() -> Dict[str, Any]:
    """
    Logout from YouTube and clear authentication session.
    
    Returns:
        Dictionary containing logout status
    """
    if not auth_manager:
        return {"error": "Authentication not configured"}
    
    if not auth_manager.is_authenticated():
        return {"message": "Not currently authenticated"}
    
    auth_manager.logout()
    return {
        "success": True,
        "message": "Successfully logged out from YouTube"
    }

@mcp.tool()
async def check_authentication_status() -> Dict[str, Any]:
    """
    Check current YouTube authentication status.
    
    Returns:
        Dictionary containing authentication status and available features
    """
    if not auth_manager:
        return {
            "authenticated": False,
            "reason": "Authentication not configured on server",
            "available_features": ["public_search", "trending_videos", "mock_data_only"],
            "configured": False
        }
    
    is_authenticated = auth_manager.is_authenticated()
    
    result = {
        "authenticated": is_authenticated,
        "configured": True,
        "available_features": [
            "real_watch_history",
            "personalized_search", 
            "user_playlists",
            "subscription_data"
        ] if is_authenticated else [
            "public_search",
            "trending_videos",
            "mock_data_only"
        ],
        "message": "Authenticated and ready to access real YouTube data" if is_authenticated else "Not authenticated - use 'login_to_youtube' to authenticate"
    }
    
    if is_authenticated and auth_manager.current_session:
        result["user_info"] = auth_manager.current_session.user_info
        result["session_expires"] = auth_manager.current_session.expires_at.isoformat()
    
    return result

@mcp.tool()
async def get_my_watch_history(include_metadata: bool = True) -> Dict[str, Any]:
    """
    Get your YouTube watch history enriched with comprehensive video metadata for analysis.
    
    Args:
        include_metadata: Whether to include detailed video metadata from YouTube API
    
    Returns:
        Dictionary containing enriched watch history data for analysis
    """
    if not youtube_service:
        return {
            "error": "YouTube service not configured.",
            "history": []
        }
    
    try:
        # Get basic watch history (real or mock depending on auth status)
        history_resource = await get_watch_history()
        watch_history = history_resource.get('history', [])
        
        # Enrich with YouTube API metadata if requested
        if include_metadata and watch_history:
            enriched_history = await youtube_service.enrich_watch_history(watch_history)
        else:
            enriched_history = watch_history
        
        return {
            "total_videos": len(enriched_history),
            "enriched_history": enriched_history,
            "important_note": "YouTube API does not provide access to personal watch history. This data represents your channel activities (uploads, likes, favorites) instead.",
            "metadata": {
                "api_enriched": include_metadata,
                "data_ready_for_analysis": True,
                "data_source": history_resource.get('metadata', {}).get('data_source', 'unknown'),
                "authenticated": history_resource.get('metadata', {}).get('authenticated', False),
                "data_type": "channel_activities_not_watch_history",
                "suggested_analysis_approaches": [
                    "Analyze upload patterns and content creation habits",
                    "Identify content preferences through likes and favorites", 
                    "Evaluate channel engagement patterns",
                    "Discover content creation trends over time",
                    "Note: For actual watch history, use Google Takeout"
                ]
            },
            "generated_at": datetime.now().isoformat()
        }
    
    except Exception as e:
        logger.error(f"Error getting enriched watch history: {e}")
        return {
            "error": f"Failed to get enriched watch history: {str(e)}",
            "history": []
        }

@mcp.tool()
async def search_videos_advanced(
    query: str, 
    max_results: int = 25, 
    order: str = 'relevance',
    published_after: Optional[str] = None,
    duration: Optional[str] = None
) -> Dict[str, Any]:
    """
    Advanced video search with multiple parameters for comprehensive data gathering.
    
    Args:
        query: Search query string
        max_results: Maximum number of results to return
        order: Sort order (relevance, date, rating, viewCount, title)
        published_after: ISO date string to filter videos published after this date
        duration: Video duration filter (short, medium, long)
    
    Returns:
        Dictionary containing search results with metadata for analysis
    """
    if not youtube_service:
        return {
            "error": "YouTube service not configured",
            "query": query,
            "results": []
        }
    
    try:
        search_results = await youtube_service.search_videos(query, max_results, order)
        
        return {
            "query": query,
            "search_parameters": {
                "max_results": max_results,
                "order": order,
                "published_after": published_after,
                "duration": duration,
                "personalized": auth_manager and auth_manager.is_authenticated()
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
async def get_video_context(video_id: str, include_similar: bool = True) -> Dict[str, Any]:
    """
    Get comprehensive context about a specific video including details and similar content.
    
    Args:
        video_id: The YouTube video ID to analyze
        include_similar: Whether to include similar videos in the response
    
    Returns:
        Dictionary containing detailed video context for analysis
    """
    if not youtube_service:
        return {
            "error": "YouTube service not configured",
            "video_id": video_id,
            "context": {}
        }
    
    try:
        # Get detailed video information
        video_details = await youtube_service.get_video_details([video_id])
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
        channel_info = await youtube_service.get_channel_info([video['snippet']['channelId']])
        if channel_info:
            context["channel_details"] = channel_info[0]
        
        # Get similar videos if requested
        if include_similar:
            video_title = video['snippet']['title']
            channel_title = video['snippet']['channelTitle']
            search_query = f"{video_title} {channel_title}"
            similar_videos = await youtube_service.search_videos(search_query, max_results=10)
            
            # Filter out the original video
            similar_videos = [
                v for v in similar_videos 
                if v.get('id', {}).get('videoId') != video_id
            ]
            context["similar_videos"] = similar_videos
        
        return {
            "video_id": video_id,
            "context": context,
            "personalized": auth_manager and auth_manager.is_authenticated(),
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
async def get_trending_by_category(category: str = "Entertainment", region: str = "US") -> Dict[str, Any]:
    """
    Get trending videos by category and region with comprehensive metadata.
    
    Args:
        category: Video category (Entertainment, Music, Gaming, etc.)
        region: Country code (US, GB, CA, etc.)
    
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
        trending_videos = await youtube_service.get_trending_videos(region, category_id)
        
        return {
            "category": category,
            "region": region,
            "category_id": category_id,
            "trending_videos": trending_videos,
            "total_found": len(trending_videos),
            "personalized": auth_manager and auth_manager.is_authenticated(),
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
async def get_channel_analytics_data(channel_ids: List[str]) -> Dict[str, Any]:
    """
    Get comprehensive channel data for analysis.
    
    Args:
        channel_ids: List of YouTube channel IDs to analyze
    
    Returns:
        Dictionary containing detailed channel information for analysis
    """
    if not youtube_service:
        return {
            "error": "YouTube service not configured",
            "channel_data": []
        }
    
    try:
        channel_data = await youtube_service.get_channel_info(channel_ids)
        
        return {
            "total_channels": len(channel_data),
            "channel_data": channel_data,
            "personalized": auth_manager and auth_manager.is_authenticated(),
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
        logger.warning("Some features will be disabled. Set these environment variables for full functionality.")
    else:
        logger.info("YouTube authentication is fully configured and ready")
    
    logger.info("🎥 YouTube MCP Server Starting...")
    logger.info("📊 Available tools:")
    logger.info("  - login_to_youtube: Interactive authentication with automatic browser opening")
    logger.info("  - check_authentication_status: Check current login status")
    logger.info("  - get_my_watch_history: Get your real YouTube watch history")
    logger.info("  - search_videos_advanced: Search YouTube with advanced parameters")
    logger.info("  - get_trending_by_category: Get trending videos by category")
    logger.info("  - logout_from_youtube: Logout and clear session")
    
    # Run the MCP server
    mcp.run()