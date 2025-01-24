import json
from ticket_body_summarizer import lambda_handler

# Load the test event
with open("event.json", "r") as file:
    event = json.load(file)

# Call the Lambda handler function
response = lambda_handler(event, None)
print(json.dumps(response, indent=4))