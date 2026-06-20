"""
storage/vector_store.py

STUB. Belum diaktifkan di pipeline utama (lihat config.QDRANT_ENABLED).

Tujuan jangka panjang komponen ini (sesuai arsitektur awal):
- Menyimpan embedding source code chunks + past findings + known
  vulnerability patterns di Qdrant.
- Dipakai untuk RAG: saat menganalisis evidence baru, cari finding masa
  lalu yang serupa (dari proyek lain) sebagai konteks tambahan untuk GPT,
  meningkatkan konsistensi penilaian severity antar proyek.

Ini sengaja TIDAK diimplementasikan penuh di MVP supaya tidak menambah
dependency wajib (server Qdrant) untuk bisa mulai memakai pipeline.
Aktivasi: set QDRANT_URL di environment, lalu lengkapi method di bawah
menggunakan client `qdrant-client` (pip install qdrant-client) dan
embedding via `openai.embeddings.create(model="text-embedding-3-large")`.
"""

from __future__ import annotations

from config import QDRANT_ENABLED, QDRANT_URL


class VectorStore:
    def __init__(self):
        self.enabled = QDRANT_ENABLED
        if self.enabled:
            # TODO: inisialisasi qdrant_client.QdrantClient(url=QDRANT_URL)
            pass

    def upsert_code_chunk(self, chunk_id: str, text: str, metadata: dict) -> None:
        if not self.enabled:
            return
        # TODO: embed `text` via text-embedding-3-large, upsert ke collection
        raise NotImplementedError("Vector store belum diimplementasikan penuh.")

    def search_similar(self, query_text: str, top_k: int = 5) -> list[dict]:
        if not self.enabled:
            return []
        # TODO: embed query, search di Qdrant, kembalikan hasil
        raise NotImplementedError("Vector store belum diimplementasikan penuh.")
