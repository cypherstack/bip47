import 'dart:typed_data';

import 'package:dart_bs58/dart_bs58.dart';
import 'package:dart_bs58check/dart_bs58check.dart';
import 'package:hex/hex.dart';
import 'package:pointycastle/ecc/api.dart';

extension Uint8ListExt on Uint8List {
  String get toHex {
    return HEX.encode(this);
  }

  String get toBase58 {
    return bs58.encode(this);
  }

  String get toBase58Check {
    return bs58check.encode(this);
  }

  /// returns copy of byte list in reverse order
  Uint8List get reversed {
    final reversed = Uint8List(length);
    for (final byte in this) {
      reversed.insert(0, byte);
    }
    return reversed;
  }

  BigInt get toBigInt {
    BigInt number = BigInt.zero;
    for (final byte in this) {
      number = (number << 8) | BigInt.from(byte & 0xff);
    }
    return number;
  }
}

extension StringExt on String {
  Uint8List get fromHex {
    return Uint8List.fromList(HEX.decode(this));
  }

  Uint8List get fromBase58 {
    return bs58.decode(this);
  }

  Uint8List get fromBase58Check {
    return bs58check.decode(this);
  }
}

extension BigIntExt on BigInt {
  String get toHex {
    final String hex = toRadixString(16);
    if (hex.length % 2 == 0) {
      return hex;
    } else {
      return "0$hex";
    }
  }

  Uint8List get toBytes {
    BigInt number = this;
    int bytes = (number.bitLength + 7) >> 3;
    var b256 = BigInt.from(256);
    var result = Uint8List(bytes);
    for (int i = 0; i < bytes; i++) {
      result[bytes - 1 - i] = number.remainder(b256).toInt();
      number = number >> 8;
    }
    return result;
  }

  bool isScalarGroupMemberOf(ECDomainParameters ecDomainParameters) {
    return BigInt.zero <= this && this < ecDomainParameters.n;
  }
}

abstract class Util {
  /// xor two equal length lists of bytes byte by byte
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

  static void copyBytes(
    Uint8List source,
    int sourceStartingIndex,
    Uint8List destination,
    int destinationStartingIndex,
    int numberOfBytes,
  ) {
    for (int i = 0; i < numberOfBytes; i++) {
      destination[i + destinationStartingIndex] =
          source[i + sourceStartingIndex];
    }
  }

  static bool isBitSet(int byte, int pos) {
    int test = 0;
    return (setBit(test, pos) & byte) > 0;
  }

  static int setBit(int byte, int pos) {
    return (byte | (1 << pos));
  }
}
