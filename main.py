import base64
import io
import sys

import requests


def crc8_calculate(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ 0x11d
            else:
                crc <<= 1
    return crc


class Uleb128:
    """
    Класс реализующий методы кодирования/декодирования ULEB128
    """

    @staticmethod
    def encode(i: int) -> bytearray:
        assert i >= 0
        r = []
        while True:
            byte = i & 0x7f
            i = i >> 7
            if i == 0:
                r.append(byte)
                return bytearray(r)
            r.append(0x80 | byte)

    @staticmethod
    def decode(b: bytearray) -> int:
        r = 0
        for i, e in enumerate(b):
            r = r + ((e & 0x7f) << (i * 7))
        return r

    @staticmethod
    def decode_reader(r) -> (int, int):
        a = bytearray()
        while True:
            b = ord(r.read(1))
            a.append(b)
            if (b & 0x80) == 0:
                break
        return Uleb128.decode(a), len(a)


class Convert:
    """
    Класс кодирования/декодирования данных под конкретные поля JSON/Python dict
    """

    @staticmethod
    def int_to_uleb(number: int) -> bytearray:
        return Uleb128.encode(number)

    @staticmethod
    def uleb_to_int(byte_array: bytearray) -> int:
        return Uleb128.decode(byte_array)

    @staticmethod
    def ulebs_reader(byte_array: bytes, total_numbers=1) -> tuple:
        numbers = []
        position = 0
        counter = 0
        while counter != total_numbers:
            number, pos = Uleb128.decode_reader(io.BytesIO(byte_array[position:]))
            numbers.append(number)
            position += pos
            counter += 1
        return *numbers, position

    @staticmethod
    def decode_base64(base64_bytes: bytes) -> bytes:
        return base64.urlsafe_b64decode(base64_bytes + b'==')

    @staticmethod
    def encode_base64(byte_string: bytes):
        return base64.urlsafe_b64encode(byte_string).strip(b'=')

    @staticmethod
    def create_cmd_body(cmd_code: int, cmd_bytes: bytearray) -> dict:
        if cmd_code == 6:
            return dict(timestamp=Convert.uleb_to_int(cmd_bytes[:-1]))


class Parser:
    """
    Методы для представления входящих данных сервера в Python dict
    """

    @staticmethod
    def parse_packet(packet: bytes):
        """
        Метод представляет из себя генератор, который преобразует байтовую строку BASE64
        в Python словари и возвращет словари
        """
        packet = Convert.decode_base64(packet)
        shift = 0
        while shift < len(packet):
            length = packet[shift]

            payload = packet[1 + shift:length + shift + 1]
            crc8 = packet[length + shift + 1]
            if crc8_calculate(payload) != crc8:
                shift += length + 2
                continue

            src, dst, serial, shift_uleb = Convert.ulebs_reader(payload, 3)
            dev_type = payload[shift_uleb]
            cmd = payload[shift_uleb + 1]
            cmd_body = payload[shift_uleb + 2:]

            if cmd == 1 or cmd == 2:
                length_string = cmd_body[0]
                dev_name = cmd_body[1:1 + length_string].decode()
                cmd_body_dict = {'dev_name': dev_name}
                if dev_type == 2:
                    sensors = cmd_body[1 + length_string]
                    triggers = Parser.parse_sensor_array(cmd_body[1 + length_string + 1:length + shift + 1])  ###
                    cmd_body_dict['dev_props'] = {'sensors': sensors, 'triggers': triggers}
                elif dev_type == 3:
                    strings = Parser.parse_string_array(cmd_body[1 + length_string:length + shift])
                    cmd_body_dict['dev_props'] = {'dev_names': strings}
                else:
                    cmd_body_dict['dev_props'] = ''
            elif cmd == 3:
                cmd_body_dict = ''
            elif cmd == 4:
                if dev_type == 2:
                    values = Parser.parse_varuint_array(cmd_body)
                    cmd_body_dict = {'values': values}
                if dev_type == 3 or dev_type == 4 or dev_type == 5:
                    cmd_body_dict = int.from_bytes(cmd_body, 'big')
            elif cmd == 5:
                cmd_body_dict = int.from_bytes(cmd_body, 'big')

            elif cmd == 6:
                timestamp = Convert.ulebs_reader(cmd_body, 1)[0]
                cmd_body_dict = {'timestamp': timestamp}

            packet_dict = {'length': length,
                           'payload': {'src': src, 'dst': dst, 'serial': serial, 'dev_type': dev_type, 'cmd': cmd,
                                       'cmd_body': cmd_body_dict}, 'crc8': crc8}
            shift += length + 2
            yield packet_dict

    @staticmethod
    def parse_sensor_array(array: bytearray) -> list:
        length = array[0]
        shift = 1
        result_triggers = []
        for i in range(length):
            op = array[shift]
            shift += 1
            value, shift_index = Convert.ulebs_reader(array[shift:])
            shift += shift_index
            len_string = array[shift]
            shift += 1
            name = array[shift:shift + len_string]
            shift += len_string
            result_triggers.append({'op': op, 'value': value, 'name': name.decode()})

        return result_triggers

    @staticmethod
    def parse_string_array(array: bytearray) -> list:
        length = array[0]
        shift = 1
        result_names = []
        for i in range(length):
            string_length = array[shift]
            shift += 1
            name = array[shift:shift + string_length]
            shift += string_length
            result_names.append(name.decode())
        return result_names

    @staticmethod
    def parse_varuint_array(array: bytearray) -> list:
        result_varuints = []
        shift = 1
        varuints = Convert.ulebs_reader(array[shift:], 4)
        result_varuints.append(varuints[0:4])
        shift += varuints[4]
        return result_varuints


class Request:
    """
    Фабрика создания запрсов в виед байтов
    """

    @staticmethod
    def create_post(device_sender, device_reader=None, cmd=0, status=None):
        if cmd == 1 or cmd == 2:
            return Request.create_whoishere(device_sender)
        elif cmd == 3:
            return Request.create_getstatus(device_sender, device_reader)
        elif cmd == 5:
            return Request.create_setstatus(device_sender, device_reader, status)

    @staticmethod
    def create_whoishere(device_sender):
        device_sender.serial += 1
        packet = CreatePacket.create_packet(device_sender.src, device_sender.dst['broadcast'], device_sender.serial,
                                            device_sender.dev_type,
                                            device_sender.name, 1)
        return packet

    @staticmethod
    def create_getstatus(device_obj, device_reader):
        device_obj.serial += 1
        packet = CreatePacket.create_packet(device_obj.src, device_reader.src, device_obj.serial,
                                            device_reader.dev_type,
                                            device_obj.name, 3)
        return packet

    @staticmethod
    def create_setstatus(device_obj, device_reader, status):
        device_obj.serial += 1
        packet = CreatePacket.create_packet(device_obj.src, device_reader.src, device_obj.serial,
                                            device_reader.dev_type,
                                            device_obj.name, 5, status)
        return packet


class CreatePacket:

    @staticmethod
    def create_packet(src: int, dst: int, serial: int, dev_type: int, device_name: str, cmd, status=None) -> bytes:
        payload = CreatePayload.create_basic_payload(src, dst, serial, dev_type, cmd, device_name, status)
        length = len(payload).to_bytes(1, 'big')
        crc8 = crc8_calculate(payload).to_bytes(1, 'big')
        return length + payload + crc8


class CreatePayload:
    @staticmethod
    def create_basic_payload(src: int, dst: int, serial: int, dev_type: int, cmd: int, device_name: str,
                             status) -> bytes:
        src = Convert.int_to_uleb(src)
        dst = Convert.int_to_uleb(dst)
        serial = Convert.int_to_uleb(serial)
        dev_type = dev_type.to_bytes(1, 'big')
        cmd_bytes = cmd.to_bytes(1, 'big')
        if cmd == 1 or cmd == 2:
            whoishere_struct = CreatePayload.create_whoishere_struct(device_name)
            return src + dst + serial + dev_type + cmd_bytes + whoishere_struct
        elif cmd == 3:
            getstatus_struct = b''
            return src + dst + serial + dev_type + cmd_bytes + getstatus_struct
        elif cmd == 5:
            if int.from_bytes(dev_type, 'big') in (4, 5):
                setstatus_struct = status.to_bytes(1, 'big')
                return src + dst + serial + dev_type + cmd_bytes + setstatus_struct

    @staticmethod
    def create_whoishere_struct(device_name: str) -> bytes:
        dev_name = len(device_name).to_bytes(1, 'big') + bytes(device_name.encode())
        if device_name == 'HUB01':
            dev_props = b''
            return dev_name + dev_props


class DeviceSerializer:
    """
    Фабрика создания объектов устройств умного дома
    """

    @staticmethod
    def serialize(device_type: int, packet=None):
        if type(packet) == dict:
            if device_type == 2:
                return EnvSensor(packet['cmd_body']['dev_name'], packet['cmd_body']['dev_props'], 1)
            elif device_type == 3:
                return Switch(packet['cmd_body']['dev_name'], packet['src'],
                              packet['cmd_body']['dev_props']['dev_names'])
            elif device_type == 4:
                return Lamp(packet['cmd_body']['dev_name'], 1, packet['src'])
            elif device_type == 5:
                return Socket(packet['cmd_body']['dev_name'], 1, packet['src'])
            elif device_type == 6:
                return Clock(packet['cmd_body']['dev_name'], packet['src'])
        else:
            if 'lamp' in device_type.lower():
                return Lamp(device_type, 0)
            elif 'socket' in device_type.lower():
                return Socket(device_type, 0)


class SmartHub:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object.__new__(cls)
        return cls._instance

    def __init__(self, server_url: str, smart_hub_src: int):
        self.name = 'HUB01'
        self.server_url = server_url
        self.src = smart_hub_src
        self.serial = 0
        self.dev_type = 1
        self.dst = {'broadcast': 16383}
        self.devices = {2: {}, 3: {}, 4: {}, 5: {}, 6: {}}
        self.time = 0
        self.devices_end_timer = {}

    def process_packet(self, packet: dict):
        for device, time in list(self.devices_end_timer.items()):
            if self.time > time:
                device.physical_status = 0
                del self.devices_end_timer[device]

        if packet['cmd'] == 1:  # получил WHOISWHO
            if packet['cmd_body']['dev_name'] not in self.devices[packet['dev_type']]:
                new_device = DeviceSerializer.serialize(packet['dev_type'], packet)
                self.devices[packet['dev_type']][packet['cmd_body']['dev_name']] = new_device
            else:
                new_device = self.devices[packet['dev_type']][packet['cmd_body']['dev_name']]
            byte_result = b''
            self.devices_end_timer[new_device] = self.time + 300
            byte_result += Request.create_post(self, cmd=2)
            byte_result += Request.create_post(self, new_device, 3)
            return byte_result

        elif packet['cmd'] == 2:  # получил IAMHERE - отправил GETSTATUS, запустил таймер
            if packet['cmd_body']['dev_name'] not in self.devices[packet['dev_type']]:
                this_device = DeviceSerializer.serialize(packet['dev_type'], packet)
                self.devices[packet['dev_type']][packet['cmd_body']['dev_name']] = this_device
            else:
                this_device = self.devices[packet['dev_type']][packet['cmd_body']['dev_name']]
            if packet['dev_type'] != 6:
                self.devices_end_timer[this_device] = self.time + 300
                return Request.create_post(self, this_device, 3)
        elif packet['cmd'] == 4:  # получил STATUS, проверил по таймеру
            this_switch = None
            if packet['dev_type'] == 3:  # STATUS от Switch
                for switch in self.devices[3].values():
                    if switch.src == packet['src']:
                        this_switch = switch
                        break
                if this_switch in self.devices_end_timer and self.time <= self.devices_end_timer[this_switch]:
                    del self.devices_end_timer[this_switch]
                    this_switch.physical_status = packet['cmd_body']
                elif this_switch in self.devices_end_timer and self.time > self.devices_end_timer[this_switch]:
                    del self.devices_end_timer[this_switch]
                    this_switch.physical_status = 0
                else:
                    this_switch.physical_status = packet['cmd_body']
                for switch_device_connect in this_switch.connected_device:
                    if switch_device_connect in self.devices[4]:
                        device_check = self.devices[4][switch_device_connect]
                        device_check.physical_status = this_switch.physical_status
                    elif switch_device_connect in self.devices[5]:
                        device_check = self.devices[5][switch_device_connect]
                        device_check.physical_status = this_switch.physical_status
                    else:
                        new_device = DeviceSerializer.serialize(switch_device_connect)
                        self.devices[new_device.dev_type][new_device.name] = new_device

            elif packet['dev_type'] in (4, 5):  # получил STATUS от LAMP и SOCKET, проверил по таймеру
                for con_dev_name in self.devices[packet['dev_type']].values():
                    if packet['src'] == con_dev_name.src:
                        device_check = con_dev_name
                        if device_check in self.devices_end_timer and self.time <= self.devices_end_timer[device_check]:
                            device_check.physical_status = 1
                            del self.devices_end_timer[device_check]
                            device_check.logical_status = packet['cmd_body']
                        elif device_check in self.devices_end_timer and self.time > self.devices_end_timer[
                            device_check]:
                            device_check.physical_status = 0
                            del self.devices_end_timer[device_check]

            elif packet['dev_type'] == 2:
                byte_result = b''
                this_sensor = None
                for sensor in self.devices[2].values():
                    if sensor.src == packet['src']:
                        this_sensor = sensor
                        break
                if this_sensor in self.devices_end_timer and self.time <= self.devices_end_timer[this_sensor]:
                    del self.devices_end_timer[this_sensor]
                    counter = 0
                    for triggers in this_sensor.on_sensors.values():
                        if not triggers:
                            continue
                        for trigger in triggers:
                            check_status = False
                            if trigger['op'] & 0x02 == 0:
                                if packet['cmd_body']['values'][0][counter] < trigger['value']:
                                    check_status = True
                            elif trigger['op'] & 0x02 == 1:
                                if packet['cmd_body']['values'][0][counter] > trigger['value']:
                                    check_status = True
                            if check_status:
                                if trigger['name'] in self.devices[4]:
                                    device_check = self.devices[4][trigger['name']]
                                    if device_check.physical_status:
                                        device_check.logical_status = trigger['op'] & 0x01
                                        byte_result += Request.create_post(self, device_check, cmd=5,
                                                                           status=trigger['op'] & 0x01)
                                        self.devices_end_timer[device_check] = self.time + 300
                                    elif trigger['name'] in self.devices[5]:
                                        device_check = self.devices[5][trigger['name']]
                                        if device_check.physical_status:
                                            device_check.logical_status = trigger['op'] & 0x01
                                            byte_result += Request.create_post(self, device_check, cmd=5,
                                                                               status=trigger['op'] & 0x01)
                                            self.devices_end_timer[device_check] = self.time + 300
                                else:
                                    new_device = DeviceSerializer.serialize(trigger['name'])
                                    self.devices[new_device.dev_type][new_device.name] = new_device
                        counter += 1
                elif this_sensor in self.devices_end_timer and self.time > self.devices_end_timer[this_sensor]:
                    del self.devices_end_timer[this_sensor]
                    this_sensor.physical_status = 0
                return byte_result
        elif packet['cmd'] == 6:
            self.time = packet['cmd_body']['timestamp']

    def send_packet(self, packet: bytes) -> tuple:
        if len(packet) == 0:
            result = requests.post(self.server_url)
        else:
            result = requests.post(self.server_url, data=Convert.encode_base64(packet))
        return result.status_code, result.content

    def __repr__(self):
        return self.name


class EnvSensor:
    def __init__(self, name: str, sensor_elements: dict, physical_status=1):
        self.name = name
        self.src = src
        self.dev_type = 2
        self.physical_status = physical_status
        self.sensors = sensor_elements['sensors']

        self.sensor_temperature = True if self.sensors & 0x01 > 0 else False
        self.sensor_humidity = True if self.sensors & 0x02 > 0 else False
        self.sensor_illumination = True if self.sensors & 0x04 > 0 else False
        self.sensor_air = True if self.sensors & 0x08 > 0 else False
        self.on_sensors = self.check_sensors()

        self.triggers = sensor_elements['triggers']

    def check_sensors(self) -> dict:
        dict_triggers = {0: [], 1: [], 2: [], 3: []}
        for trigger in self.triggers:
            dict_triggers[(trigger['op'] & (0x04 | 0x08)) >> 2] = trigger
        return dict_triggers

    def __repr__(self):
        return self.name


class Switch:
    def __init__(self, name: str, src: int, devices: list):
        self.name = name
        self.src = src
        self.dev_type = 3
        self.physical_status = 0
        self.connected_device = devices

    def __repr__(self):
        return self.name


class Lamp:
    def __init__(self, name: str, physical_status=1, src=None):
        self.name = name
        self.src = src
        self.dev_type = 4
        self.physical_status = physical_status
        self.logical_status = 0

    def __repr__(self):
        return self.name


class Socket:
    def __init__(self, name: str, physical_status=1, src=None):
        self.name = name
        self.src = src
        self.dev_type = 5
        self.physical_status = physical_status
        self.logical_status = 0

    def __repr__(self):
        return self.name


class Clock:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = object.__new__(cls)
        return cls._instance

    def __init__(self, name: int, src: int):
        self.name = name
        self.src = src
        self.dev_type = 6

    def __repr__(self):
        return self.name


if __name__ == '__main__':
    url, src = sys.argv[1], int(sys.argv[2], 16)

    smart_hub = SmartHub(url, src)
    packet = Request.create_post(smart_hub, cmd=1)
    status, content = smart_hub.send_packet(packet)

    if status not in (200, 204):
        sys.exit(99)
    elif status == 204:
        sys.exit(0)
    while True:
        packet_bytes = b''

        for packet in Parser.parse_packet(content):
            result_bytes = smart_hub.process_packet(packet['payload'])
            if result_bytes is not None:
                packet_bytes += result_bytes

        status, content = smart_hub.send_packet(packet_bytes)
        if status not in (200, 204):
            sys.exit(99)
        elif status == 204:
            sys.exit(0)
