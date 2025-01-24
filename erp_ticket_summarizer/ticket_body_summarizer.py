import json
from transformers import pipeline

# Initialize the summarizer model
summarizer = pipeline("summarization", model="t5-small")

def lambda_handler(event, context):
    # Extract input text from the event
    text = event.get("text", "")

    if not text:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "No text provided"})
        }

    # Summarize the text
    summary = summarizer(text, max_length=130, min_length=30, do_sample=False)

    return {
        "statusCode": 200,
        "body": json.dumps({"summary": summary[0]['summary_text']})
    }
