import 'dart:typed_data';

import 'package:dart_bs58/dart_bs58.dart';
import 'package:dart_bs58check/dart_bs58check.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/macs/hmac.dart';

abstract class Util {
  static String getBip47Path(int account, [int? index]) {
    String path = "m/47'/0'/$account'";
    if (index != null) {
      path += "/$index";
    }
    return path;
  }

  static Uint8List? xor(Uint8List a, Uint8List b) {
    if (a.length != b.length) {
      return null;
    }

    Uint8List result = Uint8List(a.length);

    for (int i = 0; i < a.length; i++) {
      result[i] = a[i] ^ b[i];
    }

    return result;
  }

  static Uint8List getSha512HMAC(Uint8List a, Uint8List b) {
    final hmac = HMac(SHA512Digest(), 128);
    hmac.init(KeyParameter(a));
    return hmac.process(b);
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
    for (var n in list) {
      result +=
          (n.toRadixString(16).length == 1 ? "0" : "") + n.toRadixString(16);
    }
    return result;
  }

  static Uint8List stringToUint8List(String string) {
    List<int> list = [];
    for (var leg = 0; leg < string.length; leg = leg + 2) {
      list.add(int.parse(string.substring(leg, leg + 2), radix: 16));
    }
    return Uint8List.fromList(list);
  }
}
