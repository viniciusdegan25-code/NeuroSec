import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.services.report_service import ReportService

router = APIRouter()

@router.get("/executive-pdf", summary="Gera e faz download do Relatório Executivo em PDF do NeuroSec")
def download_executive_pdf(db: Session = Depends(get_db)):
    output_path = "neurosec_executive_report.pdf"
    try:
        pdf_file = ReportService.generate_pdf_report(db, output_path)
        return FileResponse(
            path=pdf_file,
            filename="Relatorio_Executivo_NeuroSec_ASPM.pdf",
            media_type="application/pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao gerar o relatório PDF: {str(e)}")
