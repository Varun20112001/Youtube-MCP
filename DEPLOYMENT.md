# Deployment Guide for fastmcp.cloud

This guide walks you through deploying the YouTube Suggestions MCP Server to fastmcp.cloud.

## Prerequisites

1. **fastmcp.cloud Account**: Sign up at [fastmcp.cloud](https://fastmcp.cloud)
2. **YouTube API Key**: Get from [Google Cloud Console](https://console.cloud.google.com/)
3. **CLI Tool**: Install fastmcp CLI tool

## Step-by-Step Deployment

### 1. Prepare Your Project

Ensure all files are in place:
```bash
youtube-suggestions/
├── main.py                 # Main MCP server
├── requirements.txt        # Python dependencies
├── fastmcp.json           # Deployment configuration
├── README.md              # Documentation
├── .env.example           # Environment template
└── .gitignore             # Git ignore rules
```

### 2. Install fastmcp CLI

```bash
# Or via pip
pip install fastmcp-cli

# Verify installation
fastmcp --version
```

### 3. Login to fastmcp.cloud

```bash
fastmcp login
# Follow the prompts to authenticate
```

### 4. Initialize Project

```bash
cd youtube-suggestions
fastmcp init

# This will validate your fastmcp.json configuration
```

### 5. Deploy the Server

```bash
# Deploy to staging first (recommended)
fastmcp deploy --env staging

# Or deploy directly to production
fastmcp deploy --env production
```

### 6. Set Environment Variables

```bash
# Set your YouTube API key
fastmcp env set YOUTUBE_API_KEY your_actual_youtube_api_key_here

# Optional: Set other environment variables
fastmcp env set LOG_LEVEL INFO
fastmcp env set DEFAULT_REGION US

# List all environment variables
fastmcp env list
```

### 7. Verify Deployment

```bash
# Check deployment status
fastmcp status

# View server logs
fastmcp logs

# Test the deployment
fastmcp test
```

## Configuration Details

### fastmcp.json Explained

```json
{
  "name": "youtube-suggestions-mcp",           # Unique server name
  "version": "1.0.0",                         # Version for tracking
  "description": "...",                       # Server description
  "main": "main.py",                          # Entry point file
  "runtime": "python3.11",                   # Python runtime version
  "environment": {                            # Environment variables
    "YOUTUBE_API_KEY": "${YOUTUBE_API_KEY}",  # Will be set via CLI
    "LOG_LEVEL": "INFO",
    "DEFAULT_REGION": "US"
  },
  "resources": {                              # Resource allocation
    "memory": "512MB",                        # Memory limit
    "timeout": 30                             # Request timeout (seconds)
  },
  "dependencies": {                           # How to install dependencies
    "file": "requirements.txt"               # Use requirements.txt
  },
  "health_check": {                          # Health monitoring
    "path": "/health",                       # Health check endpoint
    "interval": 30                           # Check interval (seconds)
  },
  "scaling": {                               # Auto-scaling configuration
    "min_instances": 1,                      # Minimum running instances
    "max_instances": 5                       # Maximum instances under load
  }
}
```

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `YOUTUBE_API_KEY` | Yes | YouTube Data API v3 key | `AIza...` |
| `LOG_LEVEL` | No | Logging verbosity | `INFO` |
| `DEFAULT_REGION` | No | Default region code | `US` |

## Post-Deployment Setup

### 1. Test Your Deployment

```bash
# Test the MCP server endpoints
curl https://your-deployment.fastmcp.cloud/health

# Test with MCP client
fastmcp test --endpoint https://your-deployment.fastmcp.cloud
```

### 2. Monitor Performance

```bash
# View real-time logs
fastmcp logs --follow

# Check metrics
fastmcp metrics

# View scaling events
fastmcp events
```

### 3. Configure Scaling (Optional)

```bash
# Update scaling configuration
fastmcp config update --min-instances 2 --max-instances 10

# Enable auto-scaling based on CPU
fastmcp scaling set --metric cpu --threshold 70
```

## Integration with AI Assistants

### Claude Desktop Integration

After deployment, add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "youtube-suggestions": {
      "url": "https://your-deployment.fastmcp.cloud",
      "headers": {
        "Authorization": "Bearer your_fastmcp_token"
      }
    }
  }
}
```

### Generic MCP Client Integration

```javascript
// Example MCP client configuration
const mcpClient = new MCPClient({
  endpoint: "https://your-deployment.fastmcp.cloud",
  headers: {
    "Authorization": "Bearer your_fastmcp_token"
  }
});
```

## Troubleshooting

### Common Deployment Issues

#### 1. Deployment Failed
```bash
Error: Deployment failed with status 500
```
**Solutions**:
- Check `fastmcp logs` for detailed error messages
- Verify all required files are present
- Validate `fastmcp.json` syntax

#### 2. Environment Variable Issues
```bash
Error: YOUTUBE_API_KEY not found
```
**Solutions**:
- Verify environment variables: `fastmcp env list`
- Set missing variables: `fastmcp env set YOUTUBE_API_KEY your_key`
- Check variable names match exactly

#### 3. Memory Limit Exceeded
```bash
Error: Container exceeded memory limit
```
**Solutions**:
- Increase memory in `fastmcp.json`: `"memory": "1GB"`
- Optimize your code for memory usage
- Redeploy: `fastmcp deploy`

#### 4. API Quota Issues
```bash
Error: YouTube API quota exceeded
```
**Solutions**:
- Monitor API usage in Google Cloud Console
- Implement caching to reduce API calls
- Consider upgrading your Google Cloud plan

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
# Set debug log level
fastmcp env set LOG_LEVEL DEBUG

# View detailed logs
fastmcp logs --level debug
```

## Monitoring & Maintenance

### Performance Metrics

Monitor these key metrics:
- **Response Time**: Average request duration
- **Error Rate**: Percentage of failed requests
- **Memory Usage**: RAM consumption
- **API Quota**: YouTube API usage

### Automated Monitoring

```bash
# Set up alerts for high error rates
fastmcp alerts create --metric error_rate --threshold 5 --email your@email.com

# Monitor memory usage
fastmcp alerts create --metric memory_usage --threshold 80 --slack webhook_url
```

### Updates and Maintenance

```bash
# Deploy new version
fastmcp deploy --version 1.1.0

# Rollback if needed
fastmcp rollback --version 1.0.0

# Scale during high traffic
fastmcp scale --instances 10
```

## Cost Optimization

### Resource Management

```bash
# Reduce costs during low usage
fastmcp config update --min-instances 0 --max-instances 3

# Set appropriate memory limits
fastmcp config update --memory 256MB
```

### API Usage Optimization

1. **Implement Caching**: Cache trending videos for 1 hour
2. **Batch Requests**: Combine multiple video detail requests
3. **Rate Limiting**: Implement client-side rate limiting

## Security Best Practices

### API Key Management

```bash
# Rotate API keys regularly
fastmcp env set YOUTUBE_API_KEY new_api_key_here

# Use environment-specific keys
fastmcp env set YOUTUBE_API_KEY staging_key --env staging
fastmcp env set YOUTUBE_API_KEY production_key --env production
```

### Access Control

```bash
# Set up IP restrictions (if supported)
fastmcp security ip-whitelist add 192.168.1.0/24

# Enable request logging for audit
fastmcp config update --audit-logging true
```

## Support and Resources

### Getting Help

1. **fastmcp.cloud Documentation**: [docs.fastmcp.cloud](https://docs.fastmcp.cloud)
2. **Support Tickets**: Submit via fastmcp.cloud dashboard
3. **Community Forum**: Join the MCP developer community
4. **GitHub Issues**: Report bugs in this repository

### Useful Commands Reference

```bash
# Deployment
fastmcp deploy                    # Deploy to default environment
fastmcp deploy --env production   # Deploy to specific environment
fastmcp rollback                  # Rollback to previous version

# Configuration
fastmcp env list                  # List environment variables
fastmcp env set KEY value         # Set environment variable
fastmcp config show               # Show current configuration

# Monitoring
fastmcp status                    # Check deployment status
fastmcp logs                      # View application logs
fastmcp metrics                   # View performance metrics

# Scaling
fastmcp scale --instances 5       # Manual scaling
fastmcp config update --memory 1GB # Update resource limits
```

---

**🎉 Congratulations!** Your YouTube Suggestions MCP Server is now deployed and ready to help AI assistants provide personalized video recommendations!