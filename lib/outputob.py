# -*- coding: utf-8 -*-
import codecs
import logging
import os
import sqlite3

import lib.mills as mills


class SQLiteOper(object):
    def __init__(self, dbpath="", db_is_new=False):
        """

        :param dbpath: 数据库路径
        :param db_is_new: 是否重新写数据库
        :param schemafile: 数据库模式文件
        """
        if db_is_new:

            if os.path.exists(dbpath):
                os.remove(dbpath)

        self.sqlite3_conn = sqlite3.connect(dbpath, timeout=20, isolation_level=None)

    def __del__(self):
        self.sqlite3_conn.close()

    def createTable(self, schemafile):
        with codecs.open(schemafile, mode='rb', encoding='utf-8', errors='ignore') as f:
            schema = f.read()
            self.executescript(schema)

    def executescript(self, sql_script):
        """
        execute sql script
        :param sql_script:
        :return:
        """
        self.sqlite3_conn.executescript(sql_script)

    def query(self, query_statement, operate_dict=None):
        """
        select statement
        :param query:
        :return:
        """

        cursor = self.sqlite3_conn.cursor()

        if operate_dict is not None:
            cursor.execute(query_statement, operate_dict)
        else:
            cursor.execute(query_statement)

        for line in cursor.fetchall():
            yield line

    def operate(self, operate_statement, operate_dict=None, ismany=False):
        """insert/update"""

        cursor = self.sqlite3_conn.cursor()

        if ismany:
            cursor.executemany(operate_statement, operate_dict)
        else:
            if operate_dict is not None:
                cursor.execute(operate_statement, operate_dict)
            else:
                cursor.execute(operate_statement)

        self.sqlite3_conn.commit()

    def replaceData2SQLite3(self, fields=None, tablename="", data_dict=None,
                            op="replace"):
        """
        replace/insert data to sqlite3
        :param fields:
        :param tablename:
        :param data_dict:
        :param op:
        :return:
        """
        if not tablename:
            return
        if data_dict is None:
            return

        if fields is None:
            fields = data_dict.keys()

        final_dict = {}
        for f in fields:
            final_dict[f] = unicode(data_dict.get(f, "NONE"))

        filelds_str = mills.list2str(fields)
        values_str = mills.list2str(fields, "%s,:%s")

        operate_statement = "%s into %s(%s) values (%s)" % (op, tablename,
                                                            filelds_str, values_str)

        try:
            self.operate(operate_statement=operate_statement,
                         operate_dict=final_dict)
        except Exception as e:
            content = "%s failed: %s" % (operate_statement, repr(e))
            logging.error(content)
            return

    def updateData2SQLite3(self,
                           fields=None, data_dict=None,
                           tablename=None,
                           where_fields=None
                           ):
        """
        update data into sqlite3
        :param fields:
        :param data_dict:
        :param tablename:
        :param where_fields:
        :return:
        """
        if data_dict is None:
            return

        if where_fields is None:
            content = "need where fields"
            logging.error(content)
            return content

        coloumn_list = data_dict.keys()
        if fields is not None:

            if len(fields) < len(coloumn_list):
                coloumn_list = fields

        fieldsSet = set(coloumn_list)
        wherefieldsSet = set(where_fields)
        set_fieldsSet = list(fieldsSet - wherefieldsSet)

        final_dict = {}
        for f in data_dict.keys():
            final_dict[f] = unicode(data_dict.get(f, "NONE"))

        set_str = mills.list2str(set_fieldsSet, pattern="%s,%s=:%s")
        where_str = mills.list2str(wherefieldsSet, pattern="%s,%s=:%s")

        operate_statement = "update {tablename} " \
                            "set {set_str} " \
                            "where {where_str}".format(
            tablename=tablename,
            set_str=set_str,
            where_str=where_str
        )

        try:
            self.operate(operate_statement=operate_statement,
                         operate_dict=final_dict)
        except Exception as e:
            content = "%s failed: %s" % (operate_statement, repr(e))
            logging.error(content)
            return
