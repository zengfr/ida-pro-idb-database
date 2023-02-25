来源 网络 未知
https://github.com/zengfr/ida-pro-idb-database/tree/main/demo/2
python基本能拿到源码，也就是.proto编译后的文件，一般以xxx_pb2.py的文件，打开该文件其实可以手动构造回.proto，但是有更简单的方式，直接定位到
其实就是借助pbtk，新建一个提取器，运行即可获取相应的.proto：

def walk_pb2(path):
    try:
        with open(path, 'rb') as fd:
            binr = fd.read()
    except Exception:
        return

    pb = re.findall(br'serialized_pb=_b\((.+)\)', binr)
    for item in pb:
        data = eval(b'b'+item)  # 怕了吗？
        # Parse descriptor
        proto = FileDescriptorProto()
        proto.ParseFromString(data)
        # Convert to ascii
        yield descpb_to_proto(proto)


Protobufc为例
protobufc是protobuf的C实现，在很多C代码中会常用，它与Google的实现方式不同，但是依然很好分析，它存在三个魔数：

class ProtobufMagic(object):
    PROTOBUF_C__SERVICE_DESCRIPTOR_MAGIC = 0x14159bc3
    PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC = 0x28aaeef9
    PROTOBUF_C__ENUM_DESCRIPTOR_MAGIC = 0x114315af
通过它就可以定位到对应的描述符，这里简单贴下代码：

def autoParseAllMessage():
    start_addr = get_imagebase()
    magic = ProtobufMagic.PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC
    magic = b2a_hex(pack('>I', magic)).decode()
    while True:
        addr = find_binary(start_addr, SEARCH_DOWN, magic)
        start_addr = addr + 1
        if addr == BADADDR:
            debug('scan finish...')
            break
        if not isMessage(addr):
            continue
        debug('find addr {}'.format(hex(addr)))
        try:
            parseMessageDescriptor(addr) # 解析所有message描述符
        except Exception as e:
            debug('addr {} err: {}'.format(hex(addr), e))
        auto_wait()

def parseMessageDescriptor(addr):
    STRUCT_NAME = 'ProtobufCMessageDescriptor'
    if get_type(addr) == STRUCT_NAME:
        return True
    get_int_val = partial(getFieldIntVal, addr, STRUCT_NAME)
    assert get_int_val('magic') == ProtobufMagic.PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC
    if not setType(addr, STRUCT_NAME):
        debug('set addr "{}" type "{}" failed'.format(hex(addr), STRUCT_NAME))
        return False
    n_fields = get_int_val('n_fields')
    fields_addr = get_int_val('fields')
    FIELD_DESCRIPTOR_SIZE = getStructSize('ProtobufCFieldDescriptor')
    # setStructArr(fields_addr, 'ProtobufCFieldDescriptor', n_fields)
    for i in range(n_fields):
        addr = FIELD_DESCRIPTOR_SIZE * i + fields_addr
        parseFieldDescriptor(addr) # 解析对应的域
		
struct {
  descripter;
  reserved;
  feilds[];
}
自行分析
尽管反射是默认的编译选项，但是也可以禁用反射功能，此时就不会再保存元信息了，此时就需要自己去分析...

第一步：获取数据格式
这是最关键的一步，上面已经提到protobuf在通常的使用过程中是不需要描述信息的，通过传输的数据或存在的代码就可以完全恢复出数据的格式，这个可以手动分析，直接用protoc可解码抓到的合法包：

protoc –decode_raw < cap.bin
也有在线工具[tool_1][tool_2]可以解，编程可使用blackboxprotobuf或protobuf库的解析功能，大多数时候通过它解析出结果再修修补补就可以进行测试了，也不必关注.proto文件的定义。

注：1. 在gRPC-h2中抓的包可能是压缩的无法直接解析，需要先解压再解析。 2. 可能一个包里存在多条序列化的数据，此时需要将其分割再处理，此时它可能会采用length-prefix方式组合，也可能是其他方式需要具体分析啦。