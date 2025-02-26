import asyncio
import json
import tiktoken
import openai
from app.config import OPENAI_API_KEY

# Initialize OpenAI
openai.api_key = OPENAI_API_KEY
client = openai.OpenAI(api_key=OPENAI_API_KEY)

def num_tokens_from_string(string: str, model: str = "gpt-3.5-turbo") -> int:
    """Returns the number of tokens in a text string."""
    try:
        encoding = tiktoken.encoding_for_model(model)
        return len(encoding.encode(string))
    except Exception:
        # Fallback: rough approximation (4 chars ~= 1 token)
        return len(string) // 4

def truncate_to_token_limit(text: str, max_tokens: int = 4000, model: str = "gpt-3.5-turbo") -> str:
    """Truncate text to fit within token limit."""
    if not text:
        return ""
        
    # Calculate current tokens
    current_tokens = num_tokens_from_string(text, model)
    
    # If already under limit, return as is
    if current_tokens <= max_tokens:
        return text
    
    # Otherwise, truncate - we'll use a simple ratio approach
    ratio = max_tokens / current_tokens
    new_length = int(len(text) * ratio * 0.9)  # 10% safety margin
    return text[:new_length] + "... [truncated]"

async def retry_with_exponential_backoff(
    func,
    max_retries: int = 5,
    initial_delay: float = 1,
    exponential_base: float = 2,
    max_delay: float = 60,
    jitter: bool = True,
    *args,
    **kwargs
):
    """Retry a function with exponential backoff."""
    delay = initial_delay
    
    for retry in range(max_retries):
        try:
            return await func(*args, **kwargs)
        except openai.RateLimitError as e:
            if retry == max_retries - 1:
                raise e  # Re-raise the last exception if we've exhausted retries
                
            if jitter:
                delay *= (0.5 + exponential_base - 0.5 * exponential_base)
                
            delay = min(delay, max_delay)
            print(f"Rate limit hit, retrying in {delay:.2f} seconds...")
            await asyncio.sleep(delay)
            delay *= exponential_base
        except Exception as e:
            # Don't retry on other exceptions
            print(f"Non-rate-limit error occurred: {e}")
            raise e

async def analyze_with_ai(title, description, content=""):
    """Enhanced AI analysis for cybersecurity articles with rate limit handling"""
    # Prepare the input text
    full_text = f"Title: {title}\nDescription: {description}\n"
    
    # Truncate content to avoid rate limits
    if content:
        # We'll need around 1000 tokens for the model response
        content = truncate_to_token_limit(content, max_tokens=4000)
        full_text += f"Content: {content}"
    
    # Check total tokens and truncate if necessary
    full_text = truncate_to_token_limit(full_text, max_tokens=6000)
    
    prompt = f"""
    You are a cybersecurity expert tasked with analyzing threat intelligence data.
    
    Analyze the following cybersecurity article and provide structured intelligence:
    
    {full_text}
    
    Provide a structured JSON response with the following fields:
    1. "category": The most specific category from ["Ransomware", "Phishing", "Malware", "Zero-Day Exploit", "Vulnerability", "Supply Chain Attack", "Advanced Persistent Threat", "Data Breach", "DDoS", "Insider Threat", "Nation-State Attack", "Cryptojacking", "Social Engineering", "IoT Attack", "Other"]
    2. "severity": ["Critical", "High", "Medium", "Low"]
    3. "severity_score": A numerical score from 0-10 indicating the severity
    4. "confidence": A value from 0-1 indicating confidence in your analysis
    5. "cve": Any CVE identifiers mentioned (format: CVE-YYYY-NNNNN)
    6. "affected_systems": List of affected systems, software, hardware
    7. "mitre_tactics": List of MITRE ATT&CK tactics that apply
    8. "mitre_techniques": List of MITRE ATT&CK techniques that apply
    9. "threat_actors": List of threat actors/groups mentioned or likely responsible
    10. "iocs": Any indicators of compromise mentioned
    11. "summary": A concise technical summary of the threat (max 150 words)
    12. "mitigation": Brief mitigation recommendations
    
    Return ONLY the JSON with no additional text.
    """
    
    # Use retry logic with the analysis request
    try:
        async def make_request():
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",  # Use 3.5 instead of 4o for lower rate limits
                messages=[
                    {"role": "system", "content": "You are a cybersecurity threat intelligence expert."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            return response
            
        response = await retry_with_exponential_backoff(make_request)
        
        result_text = response.choices[0].message.content.strip()
        
        try:
            # Strip any markdown formatting if present
            if result_text.startswith("```json"):
                result_text = result_text.replace("```json", "", 1)
            if result_text.endswith("```"):
                result_text = result_text.rsplit("```", 1)[0]
                
            return json.loads(result_text.strip())
        except json.JSONDecodeError:
            print(f"JSON parsing error, raw response: {result_text}")
            return {
                "category": "Other",
                "severity": "Medium",
                "severity_score": 5.0,
                "confidence": 0.5,
                "summary": "Failed to process AI response."
            }
    
    except Exception as e:
        print(f"AI analysis error: {e}")
        return {
            "category": "Other",
            "severity": "Unknown",
            "severity_score": 5.0,
            "confidence": 0.3,
            "summary": "Failed to process with AI analysis."
        }