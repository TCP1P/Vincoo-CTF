#!/usr/bin/env python3
"""
Interactive log analysis quiz service.
Participants must analyze the provided access.log and answer questions correctly.
"""

import sys

FLAG = open("flag.txt", "r").read().strip()

BANNER = """
╔════════════════════════════════════════════════════════════════╗
║             WEBSITE ATTACK LOG ANALYZER                        ║
║                                                                ║
║  Situs web kami baru saja diserang! Kami butuh bantuan Anda   ║
║  untuk menganalisis jejak yang ditinggalkan penyerang.        ║
║                                                                ║
║  Analisis file access.log dan jawab 5 pertanyaan berikut.     ║
║  Jawab semua dengan benar untuk mendapatkan flag!             ║
╚════════════════════════════════════════════════════════════════╝
"""

QUESTIONS = [
    {
        "question": "1. Apa IP address dari penyerang?",
        "answers": ["192.168.1.100"],
        "hint": "Cari IP yang melakukan request mencurigakan"
    },
    {
        "question": "2. Apa nama file webshell yang berhasil diupload dan digunakan penyerang?",
        "answers": ["cmd.php"],
        "hint": "Perhatikan request ke direktori /uploads/"
    },
    {
        "question": "3. Parameter apa yang vulnerable terhadap Local File Inclusion (LFI)?",
        "answers": ["file"],
        "hint": "Perhatikan request ke page.php"
    },
    {
        "question": "4. Berapa total request yang dilakukan oleh IP penyerang?",
        "answers": ["46"],
        "hint": "Hitung semua request dari IP yang Anda identifikasi"
    },
    {
        "question": "5. Apa endpoint pertama yang coba diakses penyerang setelah halaman utama?",
        "answers": ["robots.txt", "/robots.txt"],
        "hint": "Lihat aktivitas recon awal dari penyerang"
    }
]


def ask_question(q_data):
    """Ask a single question and validate the answer."""
    print(f"\n{q_data['question']}")
    print("> ", end="")
    sys.stdout.flush()
    
    try:
        answer = input().strip()
    except EOFError:
        return False
    
    # Normalize answer for comparison
    answer_normalized = answer.lower().strip()
    valid_answers = [a.lower().strip() for a in q_data['answers']]
    
    if answer_normalized in valid_answers:
        print("[+] Benar!")
        return True
    else:
        print(f"[-] Salah! Coba lagi lain kali.")
        return False


def main():
    """Main quiz function."""
    print(BANNER)
    
    correct = 0
    total = len(QUESTIONS)
    
    for q_data in QUESTIONS:
        if ask_question(q_data):
            correct += 1
        else:
            print(f"\n[!] Anda menjawab salah. Quiz berakhir.")
            print(f"[!] Skor Anda: {correct}/{total}")
            return
    
    print("\n" + "="*60)
    print("[+] Selamat! Anda berhasil menjawab semua pertanyaan!")
    print(f"[+] Flag: {FLAG}")
    print("="*60)


if __name__ == "__main__":
    main()
