"""Generate data/demo/05_orgB_exploitation_advisory.pdf (text-only PDF, no external dependency)."""
from pathlib import Path

LINES = [
    "Advisory: exploitation of an authentication bypass in a VPN gateway (synthetic)",
    "A critical authentication bypass (CVE-2099-7777) in the fictitious Contoso VPN gateway is exploited.",
    "Unauthenticated attackers send a crafted request to the management interface and obtain a session.",
    "Mass vulnerability scanning originated from 198.51.100.150 and 198.51.100.151.",
    "Exploited appliances received a web shell at https://vpn.contoso-gw.example/admin/shell.php",
    "Administrators must apply the vendor patch and check the appliance integrity.",
]


def build(path: Path) -> None:
    content = "BT /F1 10 Tf 50 760 Td 14 TL " + " ".join(
        "(" + ln.replace("\\", "\\\\").replace("(", "\(").replace(")", "\)") + ") Tj T*" for ln in LINES) + " ET"
    stream = content.encode("latin-1")
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            b"<< /Title (VPN gateway exploitation advisory) /Author (Organisation B) >>"]
    out, offsets = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
    out += f"trailer << /Size {len(objs) + 1} /Root 1 0 R /Info 6 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    path.write_bytes(out)


if __name__ == "__main__":
    target = Path(__file__).resolve().parents[1] / "demo" / "05_orgB_exploitation_advisory.pdf"
    build(target)
    print(f"written {target}")
