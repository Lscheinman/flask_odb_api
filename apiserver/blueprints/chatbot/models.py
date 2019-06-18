import requests
from apiserver.utils import COPILOT_AUTH, COPILOT_URL, COPILOT_DEV_TOKEN, COPILOT_POST


class ChatServer():

    def __init__(self):
        self.owner = requests.get(COPILOT_URL, headers={"Authorization": COPILOT_AUTH}).json()['results']['owner']
        self.uuid = self.owner['id']
        self.headers = {"Authorization": COPILOT_DEV_TOKEN, "x-uuid": self.uuid, "content-type": "application/json"}
        self.payload = {
            "message": {
                "type": "text",
                "content": str
            },
            "conversation_id": str,
            "log_level": "info"
        }
        self.ICON_SESSION = "sap-icon://activities"
        self.ICON_POST = "sap-icon://post"
        self.ICON_USER = "sap-icon://customer"
        self.ICON_BLACKLIST = "sap-icon://cancel"

    def send_message(self, **kwargs):
        """
        With a conversation_id and text message, get a response from the COPILOT host configured

        :param content:
        :param conversation_id:
        :return:
        """

        payload = dict(self.payload)
        payload['message']['content'] = str(kwargs['message'])
        payload['conversation_id'] = str(kwargs['conversation_id'])
        r = requests.post(COPILOT_POST, json=payload, headers=self.headers).json()['results']
        response = {
            "message": str(kwargs['message']),
            "response": r['messages'][0]['content'],
            "conversation_id": r['conversation']['id'],
            "skill": r['conversation']['skill']
        }

        return response

'''
CB = ChatBot()
CB.send_message("Hello", "test")
'''