"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt.""" 

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class BaseMessage(BaseModel):
    type: str = Field(..., description="mssg-type-identifier")
    timestamp: int = Field(..., description="timestamp-in-ms")

class Hello( BaseMessage):
    client_cert: str = Field(..., description="client-certificate-pem-string")

class ServerHello( BaseMessage):
    server_cert: str = Field(..., description="server-certificate-pem-string")

class Register( BaseMessage):
    username: str = Field(..., description="username-string")
    password_hash: str = Field(..., description="password-hash-hex-string")

class Login( BaseMessage):
    username: str = Field(..., description="username-string")
    password_hash: str = Field(..., description="password-hash-hex-string")

class DHClient( BaseMessage):
    p: str = Field(..., description="dh-prime-hex-string")
    g: str = Field(..., description="dh-generator-hex-string")
    A: str = Field(..., description="dh-client-public-key-hex-string")

class DHServer( BaseMessage):
    B: str = Field(..., description="dh-server-public-key-hex-string")

class Message( BaseMessage):
    sender: str = Field(..., description="sender-username-string")
    ciphertext: str = Field(..., description="ciphertext-base64-string")

class Receipt( BaseMessage):
    identity: str = Field(..., description="message-sender-username-string")
    transcript_hash: str = Field(..., description="transcript-sha256-hex-string")
    signature: str = Field(..., description="signature-base64-string")

if __name__ == "__main__":
    hello = Hello(type="hello", timestamp=1731500000000, client_cert="-----BEGIN CERTIFICATE-----...")
    print(hello.model_dump_json(indent=2))

    dh = DHClient(type="dh_client", timestamp=1731500000100, p="23", g="5", A="8")
    print(dh.model_dump_json(indent=2))
#------------------------------------------------
#------------------------------------------------
#to run on command line:
# python app/common/protocol.py