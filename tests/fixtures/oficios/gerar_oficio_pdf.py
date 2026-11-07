"""Gera tests/fixtures/oficios/oficio.pdf: ofício mínimo (2 páginas, Helvetica/WinAnsi)
usado em test_extractors_pdf.py. Uso: python gerar_oficio_pdf.py oficio.pdf"""
import sys

PAGES = [
    [
        "Ofício nº 1234/2026/ORG-EXEMPLO",
        "Assunto: Bloqueio de domínios e endereços IP",
        "Solicitamos o bloqueio dos domínios abaixo:",
        "1. apostas-exemplo.com.br",
        "2. www.cassino-teste.net",
        "3. https://jogo-proibido.org/pagina?id=1",
    ],
    [
        "E dos endereços IP:",
        "203.0.113.10",
        "198.51.100.0/24",
        "2001:db8::1",
        "Anexos: Lista (SEI nº 0012345)",
        "Atenciosamente,",
        "Documento assinado eletronicamente por Fulano, em 15/10/2026, às 10:00.",
    ],
]


def escape(text):
    raw = text.encode("cp1252")
    return raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def build():
    objects = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    page_ids = [4 + i * 2 for i in range(len(PAGES))]
    kids = b" ".join(b"%d 0 R" % pid for pid in page_ids)
    objects.append(b"<< /Type /Pages /Kids [" + kids + b"] /Count %d >>" % len(PAGES))
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    for lines in PAGES:
        content = b"BT /F1 12 Tf 72 760 Td 16 TL\n"
        for line in lines:
            content += b"(" + escape(line) + b") Tj T*\n"
        content += b"ET"
        page_id = len(objects) + 1
        objects.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
            b"/Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>" % (page_id + 1)
        )
        objects.append(b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return bytes(out)


if __name__ == "__main__":
    with open(sys.argv[1], "wb") as output:
        output.write(build())
