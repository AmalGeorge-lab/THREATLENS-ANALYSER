import os
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from Linux.main import linux_log_analyser

#$env:PYTHON_API_KEY="6b4f2e0b8d91c3f4a7e5d9b1c6f8a2e3d7b9c1f4e6a8d0b2c5f7e9a1d3c6b8e"
# uvicorn server:app --reload --port 4897



# uvicorn server:app --host 0.0.0.0 --port $PORT

app = FastAPI()

# Read API key from environment variable
API_KEY = os.getenv("PYTHON_API_KEY")


class AnalyseRequest(BaseModel):
  logs: str


@app.post("/analyse")
async def analyser(data: AnalyseRequest,x_api_key: str = Header(None)):
  if x_api_key != API_KEY:
    raise HTTPException(status_code=401,detail="Unauthorized")

  alerts = linux_log_analyser(data.logs)
  return alerts