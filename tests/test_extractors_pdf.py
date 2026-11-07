"""Extração de ofícios em PDF (pypdf). O fixture é gerado por fixtures/oficios/gerar_oficio_pdf.py."""

from datetime import date
from pathlib import Path

from app.extractors import extract_domains, extract_ip_addresses, extract_office_metadata, extract_pdf_text

OFICIO_PDF = Path(__file__).parent / "fixtures" / "oficios" / "oficio.pdf"


def test_texto_das_duas_paginas_com_acentos():
    lines = list(extract_pdf_text(OFICIO_PDF))
    assert lines[0] == "Ofício nº 1234/2026/ORG-EXEMPLO"
    assert "E dos endereços IP:" in lines
    assert lines[-1] == "Documento assinado eletronicamente por Fulano, em 15/10/2026, às 10:00."


def test_dominios_do_pdf():
    assert extract_domains(OFICIO_PDF) == ["apostas-exemplo.com.br", "cassino-teste.net", "jogo-proibido.org"]


def test_ips_do_pdf():
    assert extract_ip_addresses(OFICIO_PDF) == ["198.51.100.0/24", "203.0.113.10", "2001:db8::1/128"]


def test_metadados_do_oficio_em_pdf():
    assert extract_office_metadata(OFICIO_PDF) == {
        "office_number": "1234/2026/ORG-EXEMPLO",
        "sei_numbers": ["0012345"],
        "expedition_date": date(2026, 10, 15),
    }
