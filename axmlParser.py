# coding=euc-kr

# ===================== #
# - title : AndroidManifest 파싱 스크립트
# - create_date : 2016.05.30
# - end_date : 2016.06.14
# - Python 3.X Version
# - auther : Kimtaewoong
# ===================== #
# - 추가할 기능 : 로그 출력을 logger로 모두 변경하기
#

import _struct
import sys
import os
import zipfile
import copy
import logging

print_flag = False

debug_logger = logging.getLogger("debug")
debug_logger.setLevel(logging.ERROR)
debug_formatter = logging.Formatter("%(asctime)s [%(levelname)s] > %(message)s")
debug_handler = logging.StreamHandler()
debug_handler.setFormatter(debug_formatter)
debug_logger.addHandler(debug_handler)


class MultipleMainActivityError(Exception):
    def __str__(self):
        return "MainActivity가 2개 이상 발견되었습니다."

def print_process(flag, text):
    if flag is True:
        print(text)

class axml_parse:
    def __init__(self):
        ### 타입별 바이너리 헤더 정의 ###
        self.TYPE_XML = b'\x03\x00'
        self.TYPE_STRING_POOL = b'\x01\x00'
        self.TYPE_XML_RESOURCE_MAP = b'\x80\x01'
        self.TYPE_XML_START_NAMESPACE = b'\x00\x01'
        self.TYPE_XML_START_ELEMENT = b'\x02\x01'
        self.TYPE_XML_CDATA = b'\x04\x01'
        self.TYPE_XML_END_ELEMENT = b'\x03\x01'
        self.TYPE_XML_END_NAMESPACE = b'\x01\x01'
        self.NS = b"\xff\xff\xff\xff"

        ### 파싱할때 사용할 변수정의 ###
        self.OFT = 0
        self.raw_data = ""
        self.string_set = {}
        self.ELEMENT_POSITION = []
        self.ELEMENT_OBJECT_LIST = []

    def axml_getData(self, search_option):
        getData_obj = GetData(self.ELEMENT_OBJECT_LIST)
        if search_option == "package_name":
            return getData_obj.get_package_name()
        elif search_option == "permission":
            return getData_obj.get_permission()
        elif search_option == "device_admin":
            return getData_obj.get_device_admin_class()
        elif search_option == "high_priority":
            return getData_obj.get_high_priority()
        elif search_option == "check_device_admin":
            return getData_obj.check_device_admin_class()
        elif search_option == "check_priority":
            return getData_obj.check_high_priority()
        elif search_option == "main_activity":
            return getData_obj.get_main_activity()

    def run_parse(self, arg_path):
        ### 함수가 다시 사용될경우를 위해 초기화 ###
        self.OFT = 0
        self.raw_data = ""
        self.string_set = {}
        self.ELEMENT_POSITION = []
        self.ELEMENT_OBJECT_LIST = []

        zip_header = b"\x50\x4b\03\x04"

        with open(arg_path, mode="rb") as target_file:
            magic_header = target_file.read(4)

            if magic_header == zip_header:
                try:
                    zip_obj = zipfile.ZipFile(arg_path, mode='r')
                    self.raw_data = zip_obj.read("AndroidManifest.xml")
                except zipfile.BadZipFile as e:
                    debug_logger.error("[MAIN/RUN_PARSE] BadZipFile Error")
                    return -31
                except RuntimeError as e:
                    debug_logger.error("[MAIN/RUN_PARSE] %s" % e)
                    return -31
                except KeyError as e:
                    debug_logger.error("[MAIN/RUN_PARSE] %s" % e)
                    return -31
                except zipfile.zlib.error as e:
                    debug_logger.error("[MAIN/RUN_PARSE] Zlib Error :: %s" % e)

            elif magic_header == self.TYPE_XML:
                target_obj = open(arg_path, mode='rb')
                self.raw_data = target_obj.read()

            else:
                debug_logger.error("[MAIN/RUN_PARSE] FILETYPE ERROR")
                return -31

        if self.type_xml() == -1: # TYPE ERROR
            return -1

        if self.type_string_pool() == -1:
            return -31

        if self.type_resource_map() == -1:
            return -31

        try:
            self._read_xml_maindata()
        except ValueError as e:
            debug_logger.error("[MAIN/RUN_PARSE/READ_XML] ELEMENT MISMATCH : %s" % e)
            return -1

        self.xml_end_namespace()
        return 1

    def _read_xml_maindata(self):
        while True:
            header_type = self.raw_data[self.OFT : self.OFT + 2]
            if self.TYPE_XML_START_NAMESPACE == header_type:
                self.xml_start_namespace()

            elif self.TYPE_XML_START_ELEMENT == header_type:
                element_name, attr_list = self.xml_start_element()
                self.ELEMENT_POSITION.append(element_name)
                element_obj = ElementObject()
                element_obj.d_insert(now_pos=copy.deepcopy(self.ELEMENT_POSITION), attr_list=attr_list)
                self.ELEMENT_OBJECT_LIST.append(element_obj)

            elif self.TYPE_XML_END_ELEMENT == header_type:
                element_name = self.xml_end_element()
                self.ELEMENT_POSITION.remove(element_name)

            elif self.TYPE_XML_CDATA == header_type:
                self.xml_cdata()

            elif self.TYPE_XML_END_NAMESPACE == header_type:
                debug_logger.info("[MAIN/RUN_PARSE] TYPE_XML_END_NAMESPACE OK")
                break
            else:
                debug_logger.error("[MAIN/RUN_PARSE] HEADER ERROR - OFFSET : 0x%04X" % self.OFT)
                return -1


    def type_xml(self):
        TYPE_XML_SIZE = 2
        HEADER_SIZE = 2
        CHUNK_SIZE = 4

        header_type = self.read_data(TYPE_XML_SIZE)

        if self.TYPE_XML != header_type:
            debug_logger.error("[TYPEXML] ERROR")
            return -1
        else:
            debug_logger.info("[TYPEXML] OK")

        header = self.read_data(HEADER_SIZE)
        chunk  = self.read_data(CHUNK_SIZE)

        debug_logger.info("[TYPEXML] FIN")


    def type_string_pool(self):

        TYPE_STRING_POOL_SIZE = 2
        HEADER_SIZE = 2
        CHUNK_SIZE = 4
        STRING_COUNT_SIZE = 4
        STYLE_COUNT_SIZE = 4
        FLAGES_SIZE = 4
        STRING_START_SIZE = 4
        STYLES_START_SIZE = 4

        STRING_OFFSET_SIZE = 4

        OFT_TYPE_STRING_POOL = 0
        OFT_STRING_START = 0
        STRING_COUNT = 0

        header_type = self.read_data(TYPE_STRING_POOL_SIZE)
        if self.TYPE_STRING_POOL == header_type:
            debug_logger.info("[TYPE_STRING_POOL] OK")
        else:
            debug_logger.error("[TYPE_STRING_POOL] ERROR")
            return -1

        header = self.read_data(HEADER_SIZE)
        chunk = self.read_data(CHUNK_SIZE)
        string_count = self.read_data(STRING_COUNT_SIZE)
        style_count = self.read_data(STYLE_COUNT_SIZE)
        flags = self.read_data(FLAGES_SIZE)
        strings_start = self.read_data(STRING_START_SIZE)
        sytles_start = self.read_data(STYLES_START_SIZE)

        string_end = self.bytesToint(string_count)
        string_offset_list = []

        # ADD OFFSET DATA in offset_list
        for count in range(string_end):
            string_t = self.read_data(STRING_OFFSET_SIZE)
            string_offset_list.append(self.bytesToint(string_t))
        # Last String size
        string_offset_list.append(self.bytesToint(chunk) - self.bytesToint(strings_start))

        for x in range(1, len(string_offset_list)):
            string_data = self.raw_data[self.OFT : self.OFT + string_offset_list[x] - string_offset_list[x-1]]
            if string_data != b"":
                self.string_set[x-1] = self.stringDecode(string_data)
            else:
                self.string_set[x-1] = "##ERROR_STRING##"
                string_data = b"##ERROR_STRING##"
            debug_logger.debug("String [%02X] - S_OFFSET : 0x%04X E_OFFSET : 0x%04X : %s " % (x-1, self.OFT, (self.OFT + string_offset_list[x] - string_offset_list[x-1]), self.stringDecode(string_data)))
            self.OFT += string_offset_list[x] - string_offset_list[x-1]

        debug_logger.info("[TYPE_STRING_POOL] FIN")

    def type_resource_map(self):

        TYPE_XML_RESOURCE_MAP_SIZE = 2
        HEADER_SIZE = 2
        CHUNK_SIZE = 4
        RESOURCE_MAP_OFFSET_SIZE = 4

        xml_resource_map_list = []

        header_type = self.read_data(TYPE_XML_RESOURCE_MAP_SIZE)
        if self.TYPE_XML_RESOURCE_MAP == header_type:
            debug_logger.info("[TYPE_XML_RESOURCE_MAP] OK")
        else:
            debug_logger.error("[TYPE_XML_RESOURCE_MAP] ERROR")
            return -1

        header = self.read_data(HEADER_SIZE)
        chunk = self.read_data(CHUNK_SIZE)

        xml_resource_map_count = (self.bytesToint(chunk) - (TYPE_XML_RESOURCE_MAP_SIZE + HEADER_SIZE + CHUNK_SIZE))
        xml_resource_map_count = int(xml_resource_map_count / RESOURCE_MAP_OFFSET_SIZE)

        for x in range(xml_resource_map_count):
            xml_resource_map_list.append(self.read_data(RESOURCE_MAP_OFFSET_SIZE))
            debug_logger.debug("XML_RESOURCE_MAP[%d] : OFFSET : 0x%04X - %s" % (x, self.OFT, xml_resource_map_list[x]))

        debug_logger.info("[TYPE_XML_RESOURCE_MAP] FIN")

    def xml_start_namespace(self):

        TYPE_XML_START_NAMESPACE_SIZE = 2
        HEADER_SIZE = 2
        CHUNK_SIZE = 4
        LINENUMBER_SIZE = 4
        COMMENT_SIZE = 4
        PREFIX_SIZE = 4
        URI_SIZE = 4

        header_type = self.read_data(TYPE_XML_START_NAMESPACE_SIZE)
        if self.TYPE_XML_START_NAMESPACE == header_type:
            debug_logger.info("[TYPE_XML_START_NAMESPACE] OK")
        else:
            debug_logger.error("[TYPE_XML_START_NAMESPACE] ERROR")
            return -1

        header = self.read_data(HEADER_SIZE)
        chunk = self.read_data(CHUNK_SIZE)
        linenumber = self.read_data(LINENUMBER_SIZE)
        comment = self.read_data(COMMENT_SIZE)
        prefix = self.read_data(PREFIX_SIZE)
        uri = self.read_data(URI_SIZE)

        debug_logger.debug("XML_START_NAMESPACE - PREFIX : %s, URI : %s" % (self.getString(prefix), self.getString(uri)))
        debug_logger.info("[XML_START_NAMESPACE] FIN")

    def xml_start_element(self):
        TYPE_XML_START_ELEMENT_SIZE = 2
        HEADER_SIZE = 2
        CHUNK_SIZE = 4
        LINENUMBER_SIZE = 4
        COMMENT_SIZE = 4
        NS_SIZE = 4
        NAME_SIZE = 4
        ATTRIBUTE_START_SIZE = 2
        ATTRIBUTE_SIZE_SIZE = 2
        ATTRIBUTE_COUNT_SIZE = 2
        IDINDEX_SIZE = 2
        CLASSINDEX_SIZE = 2
        STYLEINDEX_SIZE = 2

        tab = '\t'

        type = self.read_data(TYPE_XML_START_ELEMENT_SIZE)
        header_size = self.read_data(HEADER_SIZE)
        chunk = self.read_data(CHUNK_SIZE)
        linenumber = self.read_data(LINENUMBER_SIZE)
        comment = self.read_data(COMMENT_SIZE)
        ns = self.read_data(NS_SIZE)
        name = self.read_data(NAME_SIZE)
        attributeStart = self.read_data(ATTRIBUTE_START_SIZE)
        attributeSize = self.read_data(ATTRIBUTE_SIZE_SIZE)
        attributeCount = self.read_data(ATTRIBUTE_COUNT_SIZE)
        idIndex = self.read_data(IDINDEX_SIZE)
        classIndex = self.read_data(CLASSINDEX_SIZE)
        styleIndex = self.read_data(STYLEINDEX_SIZE)

        attr_count = self.bytesToint(attributeCount)
        element_name = self.getString(name)
        attr_list = {}
        for x in range(attr_count):
            attr_name, attr_data = self.read_attribute()
            attr_list[attr_name] = attr_data

        debug_logger.debug("%s" % (tab), element_name, attr_list)
        return element_name, attr_list

    def read_attribute(self):
        ATTRIBUTE_NS_SIZE = 4
        ATTRIBUTE_NAME_SIZE = 4
        ATTRIBUTE_RAWVALUE_SIZE = 4
        SIZE_SIZE = 2
        NULL_SIZE = 1
        DATATYPE_SIZE = 1
        DATA_SIZE = 4

        attr_ns = self.read_data(ATTRIBUTE_NS_SIZE)
        attr_name = self.read_data(ATTRIBUTE_NAME_SIZE)
        attr_rawValue = self.read_data(ATTRIBUTE_RAWVALUE_SIZE)
        attr_size = self.read_data(SIZE_SIZE)
        attr_null = self.read_data(NULL_SIZE)
        attr_dataType = self.read_data(DATATYPE_SIZE)
        attr_data = self.read_data(DATA_SIZE)

        res_attr_name = self.string_set[self.bytesToint(attr_name)]
        res_attr_data = self.chk_attr_Datatype(attr_dataType, attr_data)

        debug_logger.debug("attr_name : %s, attr_data : %s" % (res_attr_name, res_attr_data))
        return res_attr_name, res_attr_data

    def xml_cdata(self):
        TYPE_XML_CDATA_SIZE = 2
        HEADER_SIZE = 2
        CHUNK_SIZE = 4
        LINENUMBER_SIZE = 4
        COMMENT_SIZE = 4
        DATA_SIZE = 4
        SIZE_SIZE = 2
        NULL_SIZE = 1
        DATA_TYPE_SIZE = 1

        type = self.read_data(TYPE_XML_CDATA_SIZE)
        header_size = self.read_data(HEADER_SIZE)
        chunk_size = self.read_data(CHUNK_SIZE)
        linenumber = self.read_data(LINENUMBER_SIZE)
        comment = self.read_data(COMMENT_SIZE)
        data1 = self.read_data(DATA_SIZE)
        size = self.read_data(SIZE_SIZE)
        null = self.read_data(NULL_SIZE)
        datatype = self.read_data(DATA_TYPE_SIZE)
        data2 = self.read_data(DATA_SIZE)

    def xml_end_element(self):
        TYPE_XML_END_ELEMENT_SIZE = 2
        HEADER_SIZE = 2
        CHUNK_SIZE = 4
        LINENUMBER_SIZE = 4
        COMMENT_SIZE = 4
        NS_SIZE = 4
        NAME_SIZE = 4
        tab = '\t'

        type = self.read_data(TYPE_XML_END_ELEMENT_SIZE)
        header_size = self.read_data(HEADER_SIZE)
        chunk_size = self.read_data(CHUNK_SIZE)
        linenumber = self.read_data(LINENUMBER_SIZE)
        comment = self.read_data(COMMENT_SIZE)
        ns = self.read_data(NS_SIZE)
        name = self.read_data(NAME_SIZE)

        debug_logger.debug("%s" % self.string_set[self.bytesToint(name)])
        return self.getString(name)

    def chk_attr_Datatype(self, attr_dataType, attr_data):
        TYPE_NULL = b"\x00"
        TYPE_REFERENCE = b"\x01"
        TYPE_ATTRIBUTE = b"\x02"
        TYPE_STRING = b"\x03"
        TYPE_FLOAT = b"\x04"
        TYPE_DIMENSION = b"\x05"
        TYPE_FRACTION = b"\x06"
        TYPE_FIRST_INT = b"\x10"
        TYPE_INT_DEC = b"\x10"
        TYPE_INT_HEX = b"\x11"
        TYPE_INT_BOOLEAN = b"\x12"
        TYPE_FIRST_COLOR_INT = b"\x1c"
        TYPE_INT_COLOR_ARGB8 = b"\x1c"
        TYPE_INT_COLOR_RGB8 = b"\x1d"
        TYPE_INT_COLOR_ARGB4 = b"\x1e"
        TYPE_INT_COLOR_RGB4 = b"\x1f"
        TYPE_LAST_COLOR_INT = b"\x1f"
        TYPE_LAST_INT = b"\x1f"

        if(TYPE_INT_BOOLEAN == attr_dataType):
            # Data를 입력받은다음 각 타입별로 변경
            if attr_data == b"\x00\x00\x00\x00":
                return 0
            else:
                return 1

        elif((TYPE_FIRST_COLOR_INT or
            TYPE_INT_COLOR_ARGB8 or
            TYPE_INT_COLOR_RGB8 or
            TYPE_INT_COLOR_ARGB4 or
            TYPE_INT_COLOR_RGB4 or
            TYPE_LAST_COLOR_INT) == attr_dataType):
            val = "#%08X" % self.bytesToint(attr_data)
            return val

        elif((TYPE_INT_DEC or
            TYPE_FIRST_INT or
            TYPE_LAST_INT) == attr_dataType):
            return self.bytesToint(attr_data)

        elif TYPE_INT_HEX == attr_dataType:
            return self.bytesToint(attr_data)

        elif TYPE_FLOAT == attr_dataType:
            return _struct.unpack('f', attr_data)

        elif TYPE_FRACTION == attr_dataType:
            val1 = _struct.unpack('f', attr_data)[0]
            val2 = 0x7fffffff
            return float(val1 / val2)

        elif TYPE_STRING == attr_dataType:
            return self.getString(attr_data)

        elif TYPE_ATTRIBUTE == attr_dataType:
            val = "0x%08X" % self.bytesToint(attr_data)
            return val

        elif TYPE_NULL == attr_dataType:
            return 0

        else:
            return attr_data

    def xml_end_namespace(self):
        TYPE_XML_END_NAMESPACE_SIZE = 2
        HEADER_SIZE = 2
        CHUNK_SIZE = 4
        LINENUMBER_SIZE = 4
        COMMENT_SIZE = 4
        PREFIX_SIZE = 4
        URI_SIZE = 4

        header_type = self.read_data(TYPE_XML_END_NAMESPACE_SIZE)
        header_size = self.read_data(HEADER_SIZE)
        chunk_size = self.read_data(CHUNK_SIZE)
        lineNumber = self.read_data(LINENUMBER_SIZE)
        comment = self.read_data(COMMENT_SIZE)
        prefix = self.read_data(PREFIX_SIZE)
        uri = self.read_data(URI_SIZE)

        debug_logger.debug("end namespace - prefix : %s, uri : %s" % (self.getString(prefix), self.getString(uri)))

    def bytesToint(self, bytes):
        val = int.from_bytes(bytes, byteorder='little')
        return val

    def getString(self, bytes):
        val = self.bytesToint(bytes)
        return self.string_set[val]

    def stringDecode(self, data):
        string = ""
        string_offset = 2
        string_end_offset = len(data)-2

        while string_offset < string_end_offset:
            char = data[string_offset : string_offset + 2]
            char_tmp = int.from_bytes(char, byteorder='little')
            string += chr(char_tmp)
            string_offset += 2

        return string

    def read_data(self, offset):
        r_data = self.raw_data[self.OFT : self.OFT + offset]
        self.OFT += offset
        return r_data

    def offset_print(self):
        print("0x%4X" % self.OFT)


class ElementObject:
    def __init__(self):
        self.now_pos = []
        self.attr_list = {}

    def d_insert(self, now_pos, attr_list):
        self.now_pos = now_pos
        self.attr_list = attr_list

    def call_data(self):
        return self.now_pos, self.attr_list


class GetData:
    #TODO : 전체적으로 구조를 변경해야할듯. xml 파일을 부분적으로 읽기에는 많이 불편함.
    def __init__(self, ELEMENT_OBJ):
        self.ELEMENT_OBJ = ELEMENT_OBJ

    def getElementData(self, t_element_name):
        for element in self.ELEMENT_OBJ:
            now_pos, attr_list = element.call_data()
            if now_pos[-1] == t_element_name:
                #print("%s:" % t_element_name, attr_list)
                return attr_list

    def getElementData_all(self, t_element_name):
        pos_chk = 0
        space = 0
        blank = " "
        result_element_list = []

        for element in self.ELEMENT_OBJ:
            now_pos, attr_list = element.call_data()
            space = len(now_pos)*2
            for pos in now_pos:
                if pos == t_element_name:
                    pos_chk = 1

            if pos_chk == 1:
                result_element_list.append(element)
                pos_chk = 0

        return result_element_list

    def get_package_name(self):
        manifest_attr_list = self.getElementData("manifest")
        #print(manifest_attr_list['package'])
        return manifest_attr_list.get('package')

    def get_main_activity(self):
        # 메인 액티비티를 구하기 위한 함수

        tmp_main_activity = ""
        main_activity = ""
        main_list = []
        main_flag = False
        launcher_flag = False

        # activity로 시작하는 모든 Element 호출
        activity_list = self.getElementData_all("activity")
        for activity in activity_list:

            now_pos, attr_list = activity.call_data()

            # 임시로 액티비티 이름 저장
            if now_pos[-1] == "activity":
                tmp_main_activity = attr_list.get("name")

            # action 값이 MAIN인지 확인
            if now_pos[-2] == "intent-filter" and now_pos[-1] == "action":
                if attr_list.get("name") == "android.intent.action.MAIN":
                    main_flag = True

            # category 값이 Launcher 인지 확인
            if now_pos[-2] == "intent-filter" and now_pos[-1] == "category":
                if attr_list.get("name") == "android.intent.category.LAUNCHER":
                    launcher_flag = True

            # 두개 모두 일치할 경우 메인 액티비티로 등록
            if main_flag is True and launcher_flag is True:
                #print("MAIN ACTIVITY : %s" % tmp_main_activity)
                main_activity = tmp_main_activity
                main_list.append(tmp_main_activity)
                main_flag = False
                launcher_flag = False

        # 메인 액티비티가 두개 이상 있는 앱 확인을 위해 적어놓은 코드
        #print("MAIN LIST : %s" % main_list)
        if len(main_list) >= 2:
            print("[WARNING] 2개 이상의 메인 액티비티가 발견되었습니다.\n{0}".format(main_list))
            #raise MultipleMainActivityError

        return main_activity

    def get_permission(self):
        permission_list = []

        permission_element_list = self.getElementData_all("uses-permission")
        for element in permission_element_list:
            now_pos, attr_list = element.call_data()
            permission_list.append(attr_list.get('name'))
        #print(permission_list)
        return permission_list

    def get_device_admin_class(self):

        BIND_DEVICE_ADMIN = "android.permission.BIND_DEVICE_ADMIN"
        DEVICE_ADMIN_ENABLED = "android.app.action.DEVICE_ADMIN_ENABLED"
        class_name = ""
        admin_permission_list = []

        receiver_element_list = self.getElementData_all("receiver")
        for element in receiver_element_list:
            now_pos, attr_list = element.call_data()
            if now_pos[-1] == "receiver":
                class_name = attr_list.get("name")

            if attr_list.get("permission") == BIND_DEVICE_ADMIN:
                print("%s : BIND_DEVICE Detect" % class_name)
                admin_permission_list.append(BIND_DEVICE_ADMIN)

            if now_pos[-2] == "intent-filter" and now_pos[-1] == "action":
                if attr_list["name"] == DEVICE_ADMIN_ENABLED:
                    print("%s-Intent : DEVICE_ADMIN Detect" % class_name)
                    admin_permission_list.append(DEVICE_ADMIN_ENABLED)

        return class_name, admin_permission_list

    def check_device_admin_class(self):
        BIND_DEVICE_ADMIN = "android.permission.BIND_DEVICE_ADMIN"
        DEVICE_ADMIN_ENABLED = "android.app.action.DEVICE_ADMIN_ENABLED"

        admin_count = 0

        receiver_element_list = self.getElementData_all("receiver")
        for element in receiver_element_list:
            now_pos, attr_list = element.call_data()
            if now_pos[-1] == "receiver":
                class_name = attr_list.get("name")

            if attr_list.get("permission") == BIND_DEVICE_ADMIN:
                print("%s : BIND_DEVICE Detect" % class_name)

            if now_pos[-2] == "intent-filter" and now_pos[-1] == "action":
                if attr_list["name"] == DEVICE_ADMIN_ENABLED:
                    print("%s-Intent : DEVICE_ADMIN Detect" % class_name)
                    admin_count += 1
        return admin_count

    def get_high_priority(self):
        priority = 999
        e_name = ""
        present_class_name = ""
        class_list = []
        high_priority_dict = {}

        application_element_list = self.getElementData_all("application")
        for element in application_element_list:
            now_pos, attr_list = element.call_data()
            if len(now_pos) == 3:
                e_name = now_pos[-1]
                present_class_name = (attr_list.get("name"))

            if now_pos[-1] == "intent-filter" and attr_list.get("priority") is not None:
                if attr_list.get("priority") >= 999:
                    class_list.append(present_class_name)
                    high_priority_dict[e_name] = class_list

                    #print("Priority : %d, class name : %s" % (attr_list.get("priority"), present_class_name))

        #print("High Priority list : ", high_priority_dict)
        return high_priority_dict

    def check_high_priority(self):
        priority = 999
        priority_count = 0

        application_element_list = self.getElementData_all("application")
        for element in application_element_list:
            now_pos, attr_list = element.call_data()
            if len(now_pos) == 3:
                e_name = now_pos[-1]
                present_class_name = (attr_list.get("name"))

            if now_pos[-1] == "intent-filter" and attr_list.get("priority") is not None:
                if type(attr_list.get("priority")) is not int:
                    print("priority value error")
                    return -1
                else:
                    if attr_list.get("priority") >= 999:
                        priority_count += 1

        return priority_count


def scanning_dir(path, axml_obj):
    if os.path.isfile(path):
        run_parser(path, axml_obj)

    else:
        for entry in os.scandir(path):
            if entry.is_dir() == True:
                scanning_dir(entry.path, axml_obj)
            else:
                run_parser(entry.path, axml_obj)
                # Do something..


def run_parser(f_path, axml_obj):
    global g_apk_count

    ERROR_MANIFEST_NOT_FOUND = -31

    g_apk_count += 1
    print("\n===============")
    print("[%d] Parse : %s" % (g_apk_count, f_path))
    print("===============")
    res_code = axml_obj.run_parse(f_path)
    if res_code == ERROR_MANIFEST_NOT_FOUND:
        print("[PARSE] FILE TYPE ERROR")
        return -31

    axml_obj.axml_getData("activity")
    axml_obj.axml_getData("device_admin")
    axml_obj.axml_getData("check_device_admin")
    axml_obj.axml_getData("permission")
    axml_obj.axml_getData("package_name")
    axml_obj.axml_getData("check_priority")

    print("[%d] Get data Finish\nParse Finish : %s" % (g_apk_count, f_path))


if __name__ == "__main__":
    g_apk_count = 0

    arg_path = ""
    search_value = ""

    for option in sys.argv:
        if option[0:6] == "/path=":
            tmp_path = option.split("/path=")
            arg_path = tmp_path[1]
        elif option[0:8] == "/search=":
            tmp_path = option.split('/search=')
            search_value = tmp_path[1]

    axml = axml_parse()
    scanning_dir(arg_path, axml)

    print("FIN")
