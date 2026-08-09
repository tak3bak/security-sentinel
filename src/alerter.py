import os


class Alerter:
    @staticmethod
    def send_alert(message):
        """
        Sends an alert.
        Replace the print statement with requests.post() to send to a Slack/Discord Webhook.
        """
        print(f"[ALERT] Security Sentinel Event: {message}")
        # Example for future Webhook integration:
        # requests.post("https://hooks.slack.com/...", json={"text": message})
