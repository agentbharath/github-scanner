"""
This code reads the raw input files and create documents out of them.
Then chunk them using RecursiveCharacterTextSplitter and store the respective embeddings in Chroma store
"""

import os
import json
from config import config
from langchain.schema import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
from dotenv import load_dotenv

load_dotenv()

embedding = OpenAIEmbeddings(
    model=config["EMBEDDING_MODEL"]
)

CONTENT_KEY_LIST = ['content', "description", "details"]

def parse_file(filePath: str, startStr: str, endStr: str, filter_fn = None) -> list:
    """ parse the input file"""
    data_parsed = []
    with open(filePath, "r") as f:
        temp = {}
        content_key = ""
        for line in f:
            line = line.strip()
            if line == startStr.strip() or line == "":
                continue
            elif line == endStr.strip():
                targetFound = True
                if filter_fn:
                    targetFound = filter_fn(temp)
                if targetFound:
                    data_parsed.append(temp.copy())
                temp.clear()
                content_key = ""
            else:
                if content_key:
                    temp[content_key] += " " + line.strip()
                else:
                    keyValues = line.split(':', 1)
                    temp[keyValues[0].lower()] = keyValues[1].strip()
                    if keyValues[0].lower() in CONTENT_KEY_LIST:
                        content_key = keyValues[0].lower()

        return data_parsed

def filter_fn(temp: dict) -> bool:
    """filter function to know if a given input is present in the give string"""
    return temp['package'] in temp['description'].casefold()


def create_cve_documents(parsed_cve: list) -> list:
    """Creates CVE documents from parse cve list"""
    documents = []
    for cve in parsed_cve:
        doc = Document(
            page_content=cve["description"],
            metadata = {
                "cve_id": cve["cve id"],
                "package": cve["package"],
                "severity": cve["severity"],
                "affected_versions": cve["affected versions"]
            }
        )
        documents.append(doc)
    return documents

def create_pypi_documents(parsed_pypi: list) -> list:
    """ Creates PYPI documents from parsed pypi list"""
    documents = []
    for pypi in parsed_pypi:
        doc = Document(
            page_content=pypi["details"],
            metadata = {
                "advisory_id": pypi["advisory id"],
                "package": pypi["package"],
                "severity": pypi["severity"],
                "summary": pypi["summary"],
                "affected_versions": pypi["affected versions"],
                "fix_version": pypi["fix version"]
            }
        )
        documents.append(doc)
    return documents

def create_pep_documents(parsed_pep: list) -> list:
    """Creates PEP documents from parsed pep list"""
    documents = []
    for pep in parsed_pep:
        doc = Document(
            page_content=pep["content"],
            metadata = {
                "pep_id": pep["pep id"],
                "category": pep["category"]
            }
        )
        documents.append(doc)
    return documents

def create_git_documents(parsed_git: list) -> list:
    """Creates GIT documents from parsed git list"""
    documents = []
    for git in parsed_git:
        doc = Document(
            page_content=git["content"],
            metadata = {
                "source": git["source"],
                "category": git["category"]
            }
        )
        documents.append(doc)
    return documents

def chunker(documents: list) -> list:
    """Chunks the given documents using RecursiveCharacterTextSplitter"""
    splitter = RecursiveCharacterTextSplitter(
        separators= ["\n\n", "\n", ". ", " ", ""],
        chunk_size = config["CHUNK_SIZE"],
        chunk_overlap = config["CHUNK_OVERLAP"]
    )

    return splitter.split_documents(documents)

def chroma_collection(chunks: list, collection: str) -> Chroma._collection:
    """Creates a chroma collection from respective chunks"""
    return Chroma.from_documents(
    documents=chunks,
    embedding=embedding,
    collection_name=collection,
    persist_directory="./chromaStore"
)


parsed_cve = parse_file("./raw_docs/cve.txt", "--- CVE ENTRY ---", "--- END CVE ENTRY ---", filter_fn)
parsed_git = parse_file("./raw_docs/github_best_practices.txt", "--- GITHUB BEST PRACTICE ---", "--- END GITHUB BEST PRACTICE ---")
parsed_pep = parse_file("./raw_docs/pep_standards.txt", "--- PEP STANDARD ---", "--- END PEP STANDARD ---")
parsed_pypi = parse_file("./raw_docs/pypi_advisories.txt", "--- PYPI ADVISORY ---", "--- END PYPI ADVISORY ---")

cve_documents = create_cve_documents(parsed_cve)
pypi_documents = create_pypi_documents(parsed_pypi)
pep_documents = create_pep_documents(parsed_pep)
git_documents = create_git_documents(parsed_git)

cve_chunks = chunker(cve_documents)
pypi_chunks = chunker(pypi_documents)
pep_chunks = chunker(pep_documents)
git_chunks = chunker(git_documents)

security_collection = chroma_collection(cve_chunks + pypi_chunks, "security")
pep_collection = chroma_collection(pep_chunks, "pep")
git_collection = chroma_collection(git_chunks, "github")

# db = Chroma(collection_name="security", persist_directory="./chromaStore", embedding_function=embedding)
# results = db.similarity_search("Flask vulnerability", k=3)
# for r in results:
#     print(r.page_content[:100])
#     print(r.metadata)
#     print("---")