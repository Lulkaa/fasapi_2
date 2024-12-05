import requests
from datetime import datetime, timedelta
from fastapi import FastAPI, Query
from data import es
from elasticsearch import  helpers

app = FastAPI()

@app.post('/init-db/', tags=["Init database"])
def init_db():
    response = requests.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
    response.raise_for_status()
    vulnerabilities = response.json().get("vulnerabilities", [])

    if es.indices.exists(index='vendor'):
        es.indices.delete(index='vendor')
    es.indices.create(index='vendor')

    download = [
        {"_index": 'vendor', "_source": vulnerability}
        for vulnerability in vulnerabilities
    ]
    helpers.bulk(es, download)

    return {'status': '200'}


@app.get('/info/', tags=["Info"])
def info():
    return {
        "author": "Yulia Chepak",
        "/init-db/": "Ініціалізація бази даних",
        "/info": "Інформація про додаток",
        "/get/all/": "Виводить CVE за останні 10 днів, максимум 40 записів",
        "/get/new/": "Виводить 10 найновіших CVE",
        "/get/known/": "Виводить CVE, де knownRansomwareCampaignUse = 'Known', максимум 10 записів",
        "/get/": "Виводить CVE, які містять ключове слово",
    }
@app.get('/get/all/', tags=["Last 10 days CVE"])
def all():
    days = (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d")
    dict = {
        "query": {
            "range": {
                "dateAdded": {"gte": days, "lte": datetime.now().strftime("%Y-%m-%d")}
            }
        },
        "size": 40,
        "sort": [{"dateAdded": {"order": "desc"}}]
    }
    response = es.search(index='vendor', body=dict)
    return [item["_source"] for item in response["hits"]["hits"]]


@app.get('/get/new/', tags=["Last 10 CVE"])
def new():
    dict = {
        "query": {
            "match_all": {}
        },
        "size": 10,
        "sort": [{"dateAdded": {"order": "desc"}}]
    }
    response = es.search(index='vendor', body=dict)
    return [item ["_source"] for item in response["hits"]["hits"]]


@app.get('/get/known/', tags=["Key value = known"])
def known():
    dict = {
        "query": {
            "match": {
                "knownRansomwareCampaignUse": "Known"
            }
        },
        "size": 10
    }
    response = es.search(index='vendor', body=dict)
    return [item ["_source"] for item in response["hits"]["hits"]]

@app.get('/get/', tags=["Enter keyword"])
def keyword(query: str = Query):
    dict = {
        "query": {
            "multi_match": {
                "query": query,
                "fields": ["vulnerabilityName", "shortDescription"]
            }
        },
        "size": 40
    }
    response = es.search(index='vendor', body=dict)
    return [item ["_source"] for item in response["hits"]["hits"]]

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000)