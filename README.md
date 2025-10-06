# YouTube Data Provider MCP Server

A Model Context Protocol (MCP) server that provides comprehensive YouTube data including watch history, video details, trending content, and search capabilities. Designed to supply rich data to LLMs for intelligent analysis and recommendation generation.

## 🏗️ Architecture

This MCP server follows a **data-provision architecture**:
- **MCP Role**: Provides comprehensive, enriched YouTube data with metadata
- **LLM Role**: Performs intelligent analysis and generates recommendations
- **Separation of Concerns**: Clean separation between data gathering and intelligent analysis

## 🚀 Features

- **📊 Enriched Watch History**: Retrieve user watch history with comprehensive video metadata
- **🎯 Video Context**: Get detailed information about specific videos with similar content
- **📈 Trending Data**: Access trending content by category and region with analysis metadata
- **🔍 Advanced Search**: Powerful video search with multiple parameters for data gathering
- **👥 Channel Analytics**: Comprehensive channel data for LLM analysis
- **👤 User Profiles**: User context data for personalized analysis
- **🌐 Multi-Region Support**: Support for different geographical regions
- **☁️ Cloud Deployment**: Ready for deployment on fastmcp.cloud

## 🛠️ Setup & Installation

### Local Development

1. **Clone and Setup Project**
```bash
cd youtube-suggestions
pip install -r requirements.txt
```

2. **Set Environment Variables**
```bash
# Create .env file
YOUTUBE_API_KEY=your_youtube_api_key_here
```

3. **Get YouTube API Key**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing one
   - Enable YouTube Data API v3
   - Create credentials (API Key)
   - Copy the API key to your `.env` file

4. **Run the Server**
```bash
python main.py
```

### fastmcp.cloud Deployment

1. **Prepare Configuration**
   
   Make sure your `fastmcp.json` is configured:
   ```json
   {
     "name": "youtube-data-provider",
     "description": "YouTube data provider for LLM analysis",
     "version": "1.0.0",
     "entry_point": "main.py",
     "environment_variables": {
       "YOUTUBE_API_KEY": "required"
     }
   }
   ```

2. **Deploy**
   ```bash
   # Upload to fastmcp.cloud following their deployment guide
   ```

## 📋 API Reference

### Resources

#### 1. Watch History Resource
**URI Pattern**: `watch-history://user/{user_id}`

Get comprehensive watch history for a specific user with enriched metadata.

**Response**:
```json
{
  "user_id": "user123",
  "total_videos": 3,
  "history": [
    {
      "video_id": "dQw4w9WgXcQ",
      "title": "Rick Astley - Never Gonna Give You Up",
      "channel_id": "UCuAXFkgsw1L7xaCfnd5JJOw",
      "channel_title": "Rick Astley",
      "watched_at": "2024-10-01T10:30:00Z",
      "duration_seconds": 212,
      "category": "Music",
      "watch_duration_seconds": 212,
      "watch_percentage": 100,
      "interaction": "liked",
      "tags": ["80s", "pop", "classic", "music video", "dance"]
    }
  ],
  "last_updated": "2024-10-15T14:30:00Z",
  "metadata": {
    "data_source": "mock_implementation",
    "includes_interactions": true,
    "includes_watch_duration": true,
    "includes_tags": true
  }
}
```

#### 2. User Profile Resource
**URI Pattern**: `user-profile://user/{user_id}`

Get user profile information for context in analysis.

**Response**:
```json
{
  "user_id": "user123",
  "profile": {
    "age_range": "25-34",
    "primary_language": "en",
    "region": "US",
    "timezone": "America/New_York",
    "device_types": ["mobile", "desktop", "tv"],
    "subscription_status": "premium"
  },
  "preferences": {
    "auto_play": true,
    "notifications": true,
    "quality_preference": "1080p",
    "captions": false
  },
  "generated_at": "2024-10-15T14:30:00Z"
}
```

### Tools

#### 1. Get Enriched Watch History
**Function**: `get_enriched_watch_history(user_id: str, include_metadata: bool = True)`

Get user's watch history enriched with comprehensive video metadata for LLM analysis.

**Parameters**:
- `user_id`: The user ID to get watch history for
- `include_metadata`: Whether to include detailed video metadata from YouTube API

**Returns**: Dictionary containing enriched watch history data ready for LLM analysis

#### 2. Advanced Video Search
**Function**: `search_videos_advanced(query: str, max_results: int = 25, order: str = 'relevance', published_after: Optional[str] = None, duration: Optional[str] = None)`

Advanced video search with multiple parameters for comprehensive data gathering.

**Parameters**:
- `query`: Search query string
- `max_results`: Maximum number of results to return
- `order`: Sort order (relevance, date, rating, viewCount, title)
- `published_after`: ISO date string to filter videos published after this date
- `duration`: Video duration filter (short, medium, long)

**Returns**: Dictionary containing search results with metadata for LLM analysis

#### 3. Get Video Context
**Function**: `get_video_context(video_id: str, include_similar: bool = True)`

Get comprehensive context about a specific video including details and similar content.

**Parameters**:
- `video_id`: The YouTube video ID to analyze
- `include_similar`: Whether to include similar videos in the response

**Returns**: Dictionary containing detailed video context for LLM analysis

#### 4. Get Trending by Category
**Function**: `get_trending_by_category(category: str = "Entertainment", region: str = "US")`

Get trending videos by category and region with comprehensive metadata.

**Parameters**:
- `category`: Video category (Entertainment, Music, Gaming, etc.)
- `region`: Country code (US, GB, CA, etc.)

**Returns**: Dictionary containing trending videos with analysis metadata

#### 5. Get Channel Analytics Data
**Function**: `get_channel_analytics_data(channel_ids: List[str])`

Get comprehensive channel data for analysis.

**Parameters**:
- `channel_ids`: List of YouTube channel IDs to analyze

**Returns**: Dictionary containing detailed channel information for LLM analysis

## 📊 Usage Examples

### 1. Analyzing User Viewing Patterns
```python
# Get enriched watch history for analysis
history = await get_enriched_watch_history("user123", include_metadata=True)

# The LLM can then analyze patterns like:
# - Peak viewing times
# - Content category preferences  
# - Channel loyalty
# - Engagement patterns (watch percentages)
```

### 2. Content Discovery and Recommendations
```python
# Search for content based on user interests
search_results = await search_videos_advanced(
    query="machine learning tutorials", 
    max_results=15,
    order="viewCount"
)

# Get context about a specific video
video_context = await get_video_context("dQw4w9WgXcQ", include_similar=True)

# LLM can use this data to:
# - Generate personalized recommendations
# - Identify content gaps
# - Suggest related creators
```

### 3. Trend Analysis
```python
# Get trending content for analysis
trending = await get_trending_by_category("Technology", "US")

# Get channel analytics for deeper insights
channels = await get_channel_analytics_data(["UC_channel_id_1", "UC_channel_id_2"])

# LLM can analyze:
# - Emerging trends and topics
# - Regional content preferences
# - Creator growth patterns
```

## 🤖 LLM Integration

This MCP server is designed to work with LLMs for intelligent analysis. Here's how:

### Data Flow
1. **MCP Server** → Provides rich, structured YouTube data
2. **LLM** → Analyzes data and generates insights
3. **Application** → Uses LLM insights for recommendations

### Analysis Capabilities for LLMs
- **Pattern Recognition**: Identify viewing habits and preferences
- **Content Matching**: Find similar content based on multiple factors
- **Trend Analysis**: Understand what's popular and why
- **Personalization**: Generate tailored recommendations
- **Discovery**: Help users find new content they might enjoy

### Example LLM Prompts
```
"Based on this user's watch history data, identify their top 3 content preferences and suggest 5 videos they might enjoy, explaining your reasoning."

"Analyze the trending videos data and identify emerging content themes in the Technology category."

"Compare this user's viewing patterns with the trending data to find personalized recommendations that align with current trends."
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `YOUTUBE_API_KEY` | YouTube Data API v3 key | None | Yes |
| `LOG_LEVEL` | Logging level | INFO | No |
| `DEFAULT_REGION` | Default region for trending | US | No |

### API Quotas

YouTube Data API has daily quotas. Monitor usage:
- **Search**: 100 quota units per request
- **Videos**: 1 quota unit per request
- **Channels**: 1 quota unit per request
- **Daily Limit**: 10,000 quota units (default)

### Using with fastmcp.cloud

After deploying to fastmcp.cloud, you can connect using the provided MCP endpoint:

```json
{
  "mcpServers": {
    "youtube-data-provider": {
      "url": "https://your-deployment.fastmcp.cloud",
      "apiKey": "your_fastmcp_api_key"
    }
  }
}
```

## 🎯 Benefits of This Architecture

### For Developers
- **Clean Separation**: Data provision vs. analysis logic
- **Flexible Integration**: Use with any LLM or AI system
- **Scalable**: Focus on data quality and API efficiency
- **Maintainable**: Simple, focused codebase

### For LLMs
- **Rich Context**: Comprehensive metadata for better analysis
- **Structured Data**: Consistent format for reliable processing
- **Analysis Hints**: Suggested analysis approaches included
- **Real-time Data**: Fresh information for current recommendations

### For Users
- **Better Recommendations**: LLM analysis leads to more intelligent suggestions
- **Personalized Experience**: Rich user context enables customization
- **Trend Awareness**: Access to current YouTube trends and data
- **Privacy Focused**: Data processing happens in LLM context, not stored

## 🚀 Future Enhancements

- **Real User Integration**: Connect to actual YouTube accounts (with OAuth)
- **Advanced Analytics**: More sophisticated metadata extraction
- **Caching Layer**: Improve performance with intelligent caching
- **Multi-Platform**: Extend to other video platforms
- **Real-time Updates**: WebSocket support for live data

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request