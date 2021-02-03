# coding:utf8
import os
import hashlib, base64, urllib, hmac, requests, json
import time
from elasticsearch import Elasticsearch
from lib.Log import RecodeLog
from lib.settings import ELASTICSEARCH_HOST, ELASTICSEARCH_PASSWORD, ELASTICSEARCH_PORT, ELASTICSEARCH_USER, \
    DINGDING_TOKEN, DINGDING_URL

WORD_LIST = [
    "NullpointerException", "ClassNotFoundException", "ClassNotFoundExceptio", "IndexOutOfBoundsException",
    "IllegalArgumentException", "IllegalAccessException", "ArithmeticException", "ClassCastException",
    "FileNotFoundException", "ArrayStoreException", "NoSuchMethodException", "OutOfMemoryException",
    "Exception", "NoClassDefFoundException", "SQLException", "IOException", "ArrayIndexOutOfBoundsException"
]


class ElasticObj:
    def __init__(self, user=None, passwd=None, host="127.0.0.1", port=9200):
        # 无用户名密码状态
        # self.es = Elasticsearch([ip])
        # 用户名密码状态
        if user is not None:
            self.es = Elasticsearch([host], http_auth=(user, passwd), port=port)
        else:
            self.es = Elasticsearch([host], port=port)
        self.create_cache_index(index_name="cache_index")
        self.cache_index = self.get_all_index(index_name="cache_index")

    def create_cache_index(self, index_name):
        """
        :param index_name:
        :return:
        """
        _body = {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": {
                "log": {
                    "properties": {
                        "id": {
                            "type": "long",
                            "index": "false"
                        },
                        "index_name": {
                            "type": "text",
                            "index": "false"
                        }
                    }
                }
            }
        }
        if not self.es.indices.exists(index=index_name):
            res = self.es.indices.create(
                index=index_name,
                body=_body,
                include_type_name=True
            )
            RecodeLog.info(msg=res)
        else:
            RecodeLog.info(msg="cache_index is exist!")

    def insert_data(self, index_name, data):
        """
        :param index_name:
        :param data:
        :return:
        """
        self.es.index(index=index_name, body=data, doc_type='log')

    def get_all_index(self, index_name):
        """
        :param index_name:
        :return:
        """
        doc = {
            "query": {
                "match_all": {}
            }
        }
        _searched = self.es.search(index=index_name, doc_type="log", body=doc)
        index_list = list()
        for hit in _searched['hits']['hits']:
            print(hit)
            index_list.append(hit['_source']['index_name'])
        return index_list

    def list_index(self):
        for i in self.es.indices.get_alias("filebeat*"):
            if i in self.cache_index:
                continue
            self.search_words(index=i)

    def search_words(self, index):
        """
        :param index:
        :return:
        """

        for w in WORD_LIST:
            body_request = {
                "query": {
                    "match": {
                        "message": w,
                    }
                }
            }
            data = self.es.search(index=index, body=body_request)
            if data['hits']['total']['value'] == 0:
                continue
            self.format_request(data=data['hits']['hits'])
            RecodeLog.info(msg="查询:{0},{1}".format(index, w))
        doc = {
            'id': int(time.time()),
            'index_name': index
        }
        self.insert_data(index_name="cache_index", data=doc)

    def request_data(self, data, secret, url):
        """
        :param data:
        :param secret:
        :param url:
        :return:
        """
        headers = {'Content-Type': 'application/json'}
        timestamp = long(round(time.time() * 1000))
        secret_enc = bytes(secret).encode('utf-8')
        string_to_sign = '{}\n{}'.format(timestamp, secret)
        string_to_sign_enc = bytes(string_to_sign).encode('utf-8')
        hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
        sign = urllib.quote_plus(base64.b64encode(hmac_code))
        url = "{0}&timestamp={1}&sign={2}".format(url, timestamp, sign)
        x = requests.post(url=url, data=json.dumps(data), headers=headers)
        if 'errcode' in x.json():
            if x.json()["errcode"] == 0:
                RecodeLog.info("发送请求成功!")
                return True
            else:
                RecodeLog.error("发送请求失败:{0}".format(x.content))
                return False
        else:
            if x.json()["status"] == 0:
                RecodeLog.info("发送请求成功!")
                return True
            else:
                RecodeLog.error("发送请求失败:{0}".format(x.content))
                return False

    def format_request(self, data):
        """
        :param data:
        :return:
        """
        if not isinstance(data, list):
            return False
        for i in data:
            if not isinstance(i, dict):
                continue
            index = i.pop('_index')
            print(i)
            if 'kubernetes' in i['_source']:
                send_data = {
                    "msgtype": "markdown",
                    "markdown": {
                        "title": "服务出现错误日志：{0},index:{1}".format(
                            i['_source']['kubernetes']['container']['name'],
                            index
                        ),
                        "text": "服务出现错误日志：{0}\nindex:{1}\nElasticSearchID:{2}\nPod:{3}".format(
                            i['_source']['kubernetes']['container']['name'],
                            index,
                            i['_id'],
                            i['_source']['kubernetes']['pod']['name']
                        )
                    },
                    "at": {
                        "isAtAll": True
                    }
                }
            else:
                send_data = {
                    "msgtype": "markdown",
                    "markdown": {
                        "title": "服务出现错误日志：{0},index:{1}".format(
                            i['_source']['log']['file']['path'],
                            index
                        ),
                        "text": "服务出现错误日志：{0}\nindex:{1}\nElasticSearchID:{2}".format(
                            i['_source']['log']['file']['path'],
                            index,
                            i['_id']
                        )
                    },
                    "at": {
                        "isAtAll": True
                    }
                }
            if not self.request_data(data=send_data, secret=DINGDING_TOKEN, url=DINGDING_URL):
                RecodeLog.error("开始获取ID：{0}的报警发送失败,".format(i['_id']))

            else:
                RecodeLog.error("开始获取ID：{0}的报警发送成功,".format(i['_id']))
    # def format_request(self, data):
    #     """
    #     :param data:
    #     :return:
    #     """
    #     if not isinstance(data, list):
    #         return False
    #     for i in data:
    #         if not isinstance(i, dict):
    #             continue
    #         index = i.pop('_index')
    #         ids = i.pop('_id')
    #         localtime = i['_source']['@timestamp']
    #         timeArray = time.strptime(i['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
    #         start_time = time.mktime(timeArray) - 10
    #         end_time = time.mktime(timeArray) + 10
    #         RecodeLog.info("开始获取ID：{0}的相关日志,对应的时间戳为:{1},时间范围为,开始时间:{2},结束时间:{3}".format(
    #             ids,
    #             localtime,
    #             datetime.fromtimestamp(start_time),
    #             datetime.fromtimestamp(end_time)
    #         ))
    #         # body_request = {
    #         #     "query": {
    #         #         "range": {
    #         #             "@timestamp": {
    #         #                 "from": datetime.fromtimestamp(start_time),
    #         #                 "to": datetime.fromtimestamp(end_time)
    #         #             }
    #         #         }
    #         #     }
    #         # }
    #         body_request = {
    #             "query": {
    #                 "bool": {
    #                     "must": [{
    #                         "range": {
    #                             "@timestamp": {
    #                                 "from": datetime.fromtimestamp(start_time),
    #                                 "to": datetime.fromtimestamp(end_time)
    #                             }
    #                         }
    #                     }, {
    #                         "match": {
    #                             "kubernetes.container.name": i['_source']['kubernetes']['container']['name']
    #                         }
    #                     }, {
    #                         "match": {
    #                             "kubernetes.pod.name": i['_source']['kubernetes']['pod']['name']
    #                         }
    #                     }, {
    #                         "match": {
    #                             "host.name": i['_source']['host']['name']
    #                         }
    #                     }]
    #                 }
    #             }
    #         }
    #         self.search_by_id(index=index, body=body_request)
    #         RecodeLog.info("完成获取ID：{0}的相关日志,对应的时间戳为:{1}".format(ids, localtime))

    # def search_by_id(self, index, body):
    #     """
    #     :param index:
    #     :param body:
    #     :return:
    #     """
    #     data = self.es.search(index=index, body=body)['hits']['hits']
    #     for s in data:
    #         print("当前时间为:{0},主机：{1},container:{2},pod:{3},信息内容:{4}".format(
    #             s['_source']['@timestamp'], s['_source']['host']['name'],
    #             s['_source']['kubernetes']['container']['name'],
    #             s['_source']['kubernetes']['pod']['name'], s['_source']['message']
    #         ))


def run():
    e = ElasticObj(
        user=ELASTICSEARCH_USER,
        passwd=ELASTICSEARCH_PASSWORD,
        host=ELASTICSEARCH_HOST
    )
    e.list_index()
