from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.schemas.scorecard import ScorecardMetrics
from app.services.scorecard_service import ScorecardService

router = APIRouter()

@router.get("", response_model=ScorecardMetrics, summary="Calcula e retorna as métricas em tempo real do Security Scorecard")
def get_scorecard(db: Session = Depends(get_db)):
    return ScorecardService.calculate_metrics(db)
