import os
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import FileResponse, PlainTextResponse
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.services.report_service import ReportService

router = APIRouter()

@router.get("/executive-pdf", summary="Gera e faz download do Relatório Executivo em PDF do NeuroSec 4.0")
def download_executive_pdf(db: Session = Depends(get_db)):
    output_path = "neurosec_executive_report.pdf"
    try:
        pdf_file = ReportService.generate_pdf_report(db, output_path)
        return FileResponse(
            path=pdf_file,
            filename="Relatorio_Executivo_NeuroSec_ASPM_4.0.pdf",
            media_type="application/pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao gerar o relatório PDF: {str(e)}")

@router.get("/csv", summary="Exporta o inventário completo de ameaças em formato CSV/Excel")
def download_csv_inventory(db: Session = Depends(get_db)):
    try:
        csv_data = ReportService.generate_csv_inventory(db)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=inventario_ameacas_neurosec_4.0.csv"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao gerar exportação CSV: {str(e)}")

@router.get("/cyclonedx-sbom", summary="Gera o SBOM no padrão internacional CycloneDX v1.5 JSON")
def download_cyclonedx_sbom(db: Session = Depends(get_db)):
    try:
        sbom_data = ReportService.generate_cyclonedx_sbom(db)
        return sbom_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao gerar SBOM CycloneDX: {str(e)}")
