
from idc import *
from idaapi import offflag


if __EA64__:
    ARCH_F = FF_QWRD | FF_DATA
else:
    ARCH_F = FF_DWRD | FF_DATA


def struct_adder(cls, mapper):
    if GetStrucIdByName(cls.__name__) == BADADDR:
        idx = GetLastStrucIdx() + 1
        sid = AddStruc(idx, cls.__name__)
        cls.sid = sid
        for member in mapper:
            type_flag = member[1]
            if isOff0(type_flag):
                reftype = REF_OFF64 if isQwrd(ARCH_F) else REF_OFF32
                AddStrucMember(sid, member[0], -1, type_flag, 0, get_bytes_size(type_flag), reftype=reftype)
            else:
                AddStrucMember(sid, member[0], -1, type_flag, -1, get_bytes_size(type_flag))
    else:
        cls.sid = GetStrucIdByName(cls.__name__)


def struct_maker(obj, off):
    struct_adder(obj.__class__, obj.c_struct)
    MakeUnknown(off, GetStrucSize(obj.__class__.sid), DOUNK_EXPAND)
    MakeStruct(off, GetStrucName(obj.__class__.sid))


# noinspection PyPep8Naming
class QMetaObjectPrivate:
    """
struct QMetaObjectPrivate
{
    // revision 7 is Qt 5.0 everything lower is not supported
    enum { OutputRevision = 7 }; // Used by moc, qmetaobjectbuilder and qdbus

    int revision;
    int className;
    int classInfoCount, classInfoData;
    int methodCount, methodData;
    int propertyCount, propertyData;
    int enumeratorCount, enumeratorData;
    int constructorCount, constructorData;
    int flags;
    int signalCount;
    enum DisconnectType { DisconnectAll, DisconnectOne };
};

QMetaMethod QMetaObject::method(int index) const
{
    int i = index;
    i -= methodOffset();
    if (i < 0 && d.superdata)
        return d.superdata->method(index);

    QMetaMethod result;
    if (i >= 0 && i < priv(d.data)->methodCount) {
        result.mobj = this;
        result.handle = priv(d.data)->methodData + 5*i;
    }
    return result;
}


"""
    c_struct = [("revision", FF_DATA | FF_DWRD),
                ("className", FF_DATA | FF_DWRD),
                ("classInfoCount", FF_DATA | FF_DWRD),
                ("classInfoData", FF_DATA | FF_DWRD),
                ("methodCount", FF_DATA | FF_DWRD),
                ("methodData", FF_DATA | FF_DWRD),
                ("propertyCount", FF_DATA | FF_DWRD),
                ("propertyData", FF_DATA | FF_DWRD),
                ("enumeratorCount", FF_DATA | FF_DWRD),
                ("enumeratorData", FF_DATA | FF_DWRD),
                ("constructorCount", FF_DATA | FF_DWRD),
                ("constructorData", FF_DATA | FF_DWRD),
                ("flags", FF_DATA | FF_DWRD),
                ("signalCount", FF_DATA | FF_DWRD)]

    # todo: when superdata is not null
    def __init__(self, offset, str_data):
        self.offset = offset
        struct_map(self, self.c_struct, offset)
        struct_maker(self, offset)
        cmmt = """CLASS: %s
MethodCount: %d PropertyCount: %d EnumCount: %d
ConstructorCount: %d SignalCount: %d""" % (str_data[self.className].string,
    self.methodCount, self.propertyCount, self.enumeratorCount,
    self.constructorCount, self.signalCount)
        # print(cmmt)
        # S = 'ExtLinB(%d, 0, "%s")' % (offset, cmmt)
        # print(S)
        # idaapi.run_statements(S)
        MakeComm(offset, cmmt)

def displayMetaData(data_addr):
    parser = QtMetaParser(data_addr)
    parser.make_qmetaobjecprivate()
    pass


# TODO: when superdata is not null
class QtMetaParser:
    def __init__(self, d_offset):
        self.d_offset = d_offset
        self.d = QMetaObject__d(d_offset)
        self.str_data = self.get_str_data(self.d.stringdata)
        self.qmeta_obj_pri = QMetaObjectPrivate(self.d.data, self.str_data)
        class_name = self.str_data[self.qmeta_obj_pri.className].string
        class_spc = class_name + "::"
        MakeName(d_offset, class_name)
        MakeName(self.d.stringdata, class_spc + "stringdata")
        MakeName(self.d.data, class_spc + "data")
        if not Name(self.d.metacall).startswith("nullsub"):
            MakeName(self.d.metacall, class_spc + "metacall")

    @staticmethod
    def get_str_data(str_off):
        start = str_off
        str_data = []
        while Dword(start) == 0xFFFFFFFF and Dword(start + 8) == 0:
            str_data.append(QArrayData(start))
            start += QArrayData.size
        return str_data

    def make_qmetaobjecprivate(self):
        # parse method
        start = self.qmeta_obj_pri.offset + (self.qmeta_obj_pri.methodData << 2)
        method_data = []
        for off in range(start, start + 4 * 5 * self.qmeta_obj_pri.methodCount, 4 * 5):
            qmthd = QMetaMethod(off, self.d.data, self.str_data)
            # MakeComm(qmthd.offset, "METHOD_%d " % len(method_data) + Comment(qmthd.offset))
            method_data.append(qmthd)


class Enum:
    def __init__(self, **entries): self.__dict__.update(entries)


class QMetaMethod:
    c_struct = [("name", FF_DATA | FF_DWRD),
                ("parameterCount", FF_DATA | FF_DWRD),
                ("typesDataIndex", FF_DATA | FF_DWRD),
                ("tag", FF_DATA | FF_DWRD),
                ("flag", FF_DATA | FF_DWRD)]
    PropertyFlags = Enum(
        Invalid=0x00000000, Readable=0x00000001, Writable=0x00000002, Resettable=0x00000004,
        EnumOrFlag=0x00000008, StdCppSet=0x00000100, Override=0x00000200, Constant=0x00000400,
        Final=0x00000800, Designable=0x00001000, ResolveDesignable=0x00002000, Scriptable=0x00004000,
        ResolveScriptable=0x00008000, Stored=0x00010000, ResolveStored=0x00020000, Editable=0x00040000,
        ResolveEditable=0x00080000, User=0x00100000, ResolveUser=0x00200000, Notify=0x00400000,
        Revisioned=0x00800000
    )
    MethodFlags = Enum(
        AccessPrivate=0x00, AccessProtected=0x01, AccessPublic=0x02, AccessMask=0x03,
        MethodMethod=0x00, MethodSignal=0x04, MethodSlot=0x08, MethodConstructor=0x0c, MethodTypeMask=0x0c,
        MethodCompatibility=0x10, MethodCloned=0x20, MethodScriptable=0x40, MethodRevisioned=0x80
    )
    MethodTypesDict = {0x00: "METHOD", 0x04: "SIGNAL", 0x08: "SLOT", 0x0c: "CONSTRUCTOR"}
    MethodAccessDict = {0x00: "Private", 0x01: "Protected", 0x02: "Public"}

    QMetaType_map = {
        0: "UnknownType", 1: "Bool", 2: "Int", 3: "UInt", 4: "LongLong", 5: "ULongLong", 6: "Double",
        7: "QChar", 8: "QVariantMap", 9: "QVariantList", 10: "QString", 11: "QStringList",
        12: "QByteArray", 13: "QBitArray", 14: "QDate", 15: "QTime", 16: "QDateTime", 17: "QUrl",
        18: "QLocale", 19: "QRect", 20: "QRectF", 21: "QSize", 22: "QSizeF", 23: "QLine", 24: "QLineF",
        25: "QPoint", 26: "QPointF", 27: "QRegExp", 28: "QVariantHash", 29: "QEasingCurve", 30: "QUuid",
        31: "VoidStar", 32: "Long", 33: "Short", 34: "Char", 35: "ULong", 36: "UShort", 37: "UChar",
        38: "Float", 39: "QObjectStar", 40: "SChar", 41: "QVariant", 42: "QModelIndex", 43: "Void",
        44: "QRegularExpression", 45: "QJsonValue", 46: "QJsonObject", 47: "QJsonArray", 
        48: "QJsonDocument", 49: "QByteArrayList", 64: "QFont", 65: "QPixmap", 66: "QBrush", 
        67: "QColor", 68: "QPalette", 69: "QIcon", 70: "QImage", 71: "QPolygon", 72: "QRegion",
        73: "QBitmap", 74: "QCursor", 75: "QKeySequence", 76: "QPen", 77: "QTextLength",
        78: "QTextFormat", 79: "QMatrix", 80: "QTransform", 81: "QMatrix4x4", 82: "QVector2D",
        83: "QVector3D", 84: "QVector4D", 85: "QQuaternion", 86: "QPolygonF", 121: "QSizePolicy",
        1024: "User"
    }

    def get_type_str(self):
        method_type = self.flag & self.MethodFlags.MethodTypeMask
        cmmt = self.MethodTypesDict[method_type]
        access = self.flag & self.MethodFlags.AccessMask
        cmmt += " " + self.MethodAccessDict[access]
        if self.flag & self.MethodFlags.MethodCompatibility:
            cmmt += " Compatibility"
        elif self.flag & self.MethodFlags.MethodCloned:
            cmmt += " Cloned"
        elif self.flag & self.MethodFlags.MethodScriptable:
            cmmt += " Sciptable"
        elif self.flag & self.MethodFlags.MethodRevisioned:
            cmmt += " Revisioned"
        return cmmt

    def get_type(self, type_off, str_data_off):
        MakeUnknown(type_off, 4, DOUNK_EXPAND)
        type_info = Dword(type_off)
        if type_info in QMetaMethod.QMetaType_map:
            t = self.QMetaType_map[type_info]
        elif type_info & 0x80000000:
            type_info &= 0x7FFFFFFF
            t = str_data_off[type_info].string
        MakeComm(type_off, t)
        MakeDword(type_off)
        return t

    def __init__(self, off, data_off, str_data_off):
        self.offset = off
        struct_map(self, self.c_struct, off)
        struct_maker(self, off)

        ret_type_off = data_off + self.typesDataIndex * 4
        ret_type_str = self.get_type(ret_type_off, str_data_off)
        paras_type_off = ret_type_off + 4
        para_type_strs = []
        for i in range(self.parameterCount):
            para_type_off = paras_type_off + i * 4
            para_type = self.get_type(para_type_off, str_data_off)
            para_type_strs.append(para_type)

        para_name_strs = []
        paras_name_off = paras_type_off + self.parameterCount * 4
        for i in range(self.parameterCount):
            para_name_off = paras_name_off + i * 4
            MakeUnknown(para_name_off, 4, DOUNK_EXPAND)
            MakeDword(para_name_off)
            para_name = str_data_off[Dword(para_name_off)].string
            MakeComm(para_name_off, para_name)
            para_name_strs.append(para_name)

        paras_strs = map(lambda x, y: "%s %s" % (x, y), para_type_strs, para_name_strs)
        MakeComm(off, "%s %s %s(%s)" % (self.get_type_str(), ret_type_str,
            str_data_off[self.name].string, ", ".join(paras_strs)))


def get_bytes_size(data_flag):
    if isByte(data_flag):
        bytes_len = 1
    elif isWord(data_flag):
        bytes_len = 2
    elif isDwrd(data_flag):
        bytes_len = 4
    elif isQwrd(data_flag):
        bytes_len = 8
    return bytes_len

type_maker = {1: Byte, 2: Word, 4: Dword, 8: Qword}

def struct_map(obj, stru, off):
    for member in stru:
        bytes_len = get_bytes_size(member[1])
        setattr(obj, member[0], type_maker[bytes_len](off))
        off += bytes_len
    return off


class QMetaObject__d:
    """
struct QMetaObject::d { // private data
    const QMetaObject *superdata;
    const QByteArrayData *stringdata;
    const uint *data;
    StaticMetacallFunction static_metacall;
    const QMetaObject * const *relatedMetaObjects;
    void *extradata; //reserved for future use
} d;
"""
    c_struct = [("superdata", offflag() | FF_DATA | ARCH_F),
                ("stringdata", offflag() | FF_DATA | ARCH_F),
                ("data", offflag() | FF_DATA | ARCH_F),
                ("metacall", offflag() | FF_DATA | ARCH_F),
                ("relatedMetaObjects", offflag() | FF_DATA | ARCH_F),
                ("extradata", offflag() | FF_DATA | ARCH_F)]

    def __init__(self, offset):
        struct_map(self, self.c_struct, offset)
        struct_maker(self, offset)


class QArrayData:
    """
struct QArrayData
{
    QtPrivate::RefCount ref;
    int size;
    uint alloc : 31;
    uint capacityReserved : 1;

    qptrdiff offset; // in bytes from beginning of header
};
static inline const QByteArray stringData(const QMetaObject *mo, int index)
{
    Q_ASSERT(priv(mo->d.data)->revision >= 7);
    const QByteArrayDataPtr data = { const_cast<QByteArrayData*>(&mo->d.stringdata[index]) };
    Q_ASSERT(data.ptr->ref.isStatic());
    Q_ASSERT(data.ptr->alloc == 0);
    Q_ASSERT(data.ptr->capacityReserved == 0);
    Q_ASSERT(data.ptr->size >= 0);
    return data;
}

"""
    if __EA64__:
        size = 24
    else:
        size = 16

    c_struct = [("ref", FF_DATA | FF_DWRD),
            ("size", FF_DATA | ARCH_F),
            ("alloc__capRved", FF_DATA | FF_DWRD),
            ("offset", FF_DATA | ARCH_F) ]


    def __init__(self, beg_off):
        struct_map(self, self.c_struct, beg_off)
        struct_maker(self, beg_off)
        self.string = GetString(beg_off + self.offset)

        alloc = 0x7FFFFFFF & self.alloc__capRved
        capacityReserved = self.alloc__capRved >> 31

        cmmt = "String: %s, alloc: %d, capRvrsd %d" % (self.string, capacityReserved, alloc)
        MakeComm(beg_off, cmmt)


    def __repr__(self):
        return "%s" % self.string



addrtoparse = ScreenEA()
if addrtoparse != 0:
    displayMetaData(addrtoparse)
