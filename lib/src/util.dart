import 'dart:typed_data';

import 'package:dart_bs58/dart_bs58.dart';
import 'package:dart_bs58check/dart_bs58check.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/macs/hmac.dart';

extension Uint8ListExt on Uint8List {
  String get toHex {
    // return hex.encode(this);
    return Util.uint8listToString(this);
  }

  String get toBase58 {
    return Util.encodeBase58(this);
  }

  String get toBase58Check {
    return Util.encodeBase58Check(this);
  }

  /// returns copy of byte list in reverse order
  Uint8List get reversed {
    final reversed = Uint8List(length);
    for (final byte in this) {
      reversed.insert(0, byte);
    }
    return reversed;
  }
}

extension StringExt on String {
  Uint8List get fromHex {
    // return Uint8List.fromList(hex.decode(this));
    return Util.stringToUint8List(this);
  }

  Uint8List get fromBase58 {
    return Util.decodeBase58(this);
  }

  Uint8List get fromBase58Check {
    return Util.decodeBase58Check(this);
  }
}

abstract class Util {
  static String getBip47Path(int account, [int? index]) {
    String path = "m/47'/0'/$account'";
    if (index != null) {
      path += "/$index";
    }
    return path;
  }

  static Uint8List xor(Uint8List a, Uint8List b) {
    if (a.length != b.length) {
      throw ArgumentError("Byte count does not match");
    }

    Uint8List result = Uint8List(a.length);

    for (int i = 0; i < a.length; i++) {
      result[i] = a[i] ^ b[i];
    }

    return result;
  }

  static Uint8List getSha512HMAC(Uint8List key, Uint8List data) {
    final hmac = HMac(SHA512Digest(), 128);
    hmac.init(KeyParameter(key));
    return hmac.process(data);
  }

  static void copyBytes(
    Uint8List source,
    int sourceIndex,
    Uint8List destination,
    int destinationIndex,
    int length,
  ) {
    for (int i = 0; i < length; i++) {
      destination[i + destinationIndex] = source[i + sourceIndex];
    }
  }

  static BigInt bytesToInt(Uint8List data) {
    BigInt num = BigInt.zero;
    for (final byte in data) {
      num = (num << 8) | BigInt.from(byte & 0xff);
    }
    return num;
  }

  static Uint8List intToBytes(BigInt num) {
    int bytes = (num.bitLength + 7) >> 3;
    var b256 = BigInt.from(256);
    var result = Uint8List(bytes);
    for (int i = 0; i < bytes; i++) {
      result[bytes - 1 - i] = num.remainder(b256).toInt();
      num = num >> 8;
    }
    return result;
  }

  static String encodeBase58Check(Uint8List data) {
    return bs58check.encode(data);
  }

  static String encodeBase58(Uint8List data) {
    return bs58.encode(data);
  }

  static Uint8List decodeBase58Check(String value) {
    return bs58check.decode(value);
  }

  static Uint8List decodeBase58(String value) {
    return bs58.decode(value);
  }

  static String uint8listToString(Uint8List list) {
    String result = "";
    for (final n in list) {
      result +=
          (n.toRadixString(16).length == 1 ? "0" : "") + n.toRadixString(16);
    }
    return result;
  }

  static Uint8List stringToUint8List(String string) {
    List<int> list = [];
    for (int leg = 0; leg < string.length; leg = leg + 2) {
      list.add(int.parse(string.substring(leg, leg + 2), radix: 16));
    }
    return Uint8List.fromList(list);
  }

  static String bigIntoToHex(BigInt value) {
    final String hex = value.toRadixString(16);
    if (hex.length % 2 == 0) {
      return hex;
    } else {
      return "0$hex";
    }
  }
}
