import 'dart:typed_data';

import 'package:bip32/bip32.dart' as bip32;
import 'package:bip39/bip39.dart' as bip39;
import 'package:bip47/bip47.dart';
import 'package:bip47/src/util.dart';
import 'package:bitcoindart/bitcoindart.dart';
// import 'package:pointycastle/pointycastle.dart';
import 'package:bitcoindart/src/utils/script.dart' as bscript;
import 'package:test/test.dart';

const String kPath = "m/47'/0'/0'";

// test data chosen from:
// https://gist.github.com/SamouraiDev/6aad669604c5930864bd
// https://github.com/SamouraiDev/OBPPrfc05/blob/main/TestVectorsV3.java
// https://github.com/rust-bitcoin/rust-bip47/blob/master/src/lib.rs#L718-L720
// https://github.com/sparrowwallet/drongo/blob/master/src/test/java/com/sparrowwallet/drongo/bip47/PaymentCodeTest.java#L33

const String kSeedAlice =
    "response seminar brave tip suit recall often sound stick owner lottery motion";
const String kPaymentCodeAlice =
    "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";
const kNotificationAddressAlice = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW";

const String kSeedBob =
    "reward upper indicate eight swift arch injury crystal super wrestle already dentist";
const String kPaymentCodeBob =
    "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97";
const kNotificationAddressBob = "1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV";

const String kAliceDesignatedPrivateKey =
    "Kx983SRhAZpAhj7Aac1wUXMJ6XZeyJKqCxJJ49dxEbYCT4a1ozRD";

void main() {
  group("payment codes v1", () {
    test('Payment code v1 initFromPubKey', () async {
      final bip32NodeAlice = bip32.BIP32
          .fromSeed(bip39.mnemonicToSeed(kSeedAlice))
          .derivePath(kPath);

      final paymentCodeAliceV1 = PaymentCode.initFromPubKey(
          bip32NodeAlice.publicKey, bip32NodeAlice.chainCode);

      expect(
        paymentCodeAliceV1.toString(),
        kPaymentCodeAlice,
      );

      final bip32NodeBob = bip32.BIP32
          .fromSeed(bip39.mnemonicToSeed(kSeedBob))
          .derivePath(kPath);

      final paymentCodeBobV1 = PaymentCode.initFromPubKey(
          bip32NodeBob.publicKey, bip32NodeBob.chainCode);

      expect(
        paymentCodeBobV1.toString(),
        kPaymentCodeBob,
      );
    });

    test('Payment code v1 initFromPaymentCode', () async {
      final bip32NodeAlice = bip32.BIP32
          .fromSeed(bip39.mnemonicToSeed(kSeedAlice))
          .derivePath(kPath);

      final paymentCodeAliceV1 = PaymentCode.fromPaymentCode(
        kPaymentCodeAlice,
        null,
      );

      expect(paymentCodeAliceV1.getPubKey(), bip32NodeAlice.publicKey);
      expect(paymentCodeAliceV1.getChain(), bip32NodeAlice.chainCode);

      final bip32NodeBob = bip32.BIP32
          .fromSeed(bip39.mnemonicToSeed(kSeedBob))
          .derivePath(kPath);

      final paymentCodeBobV1 = PaymentCode.fromPaymentCode(
        kPaymentCodeBob,
        null,
      );

      expect(paymentCodeBobV1.getPubKey(), bip32NodeBob.publicKey);
      expect(paymentCodeBobV1.getChain(), bip32NodeBob.chainCode);
    });

    test('Payment code v1 isValid', () async {
      final paymentCodeAliceV1 = PaymentCode.fromPaymentCode(
        kPaymentCodeAlice,
        null,
      );

      final paymentCodeBobV1 = PaymentCode.fromPaymentCode(
        kPaymentCodeBob,
        null,
      );

      expect(paymentCodeBobV1.isValid(), true);
      expect(paymentCodeAliceV1.isValid(), true);
    });

    test('Payment code v1 notificationAddress', () async {
      final paymentCodeAliceV1 = PaymentCode.fromPaymentCode(
        kPaymentCodeAlice,
        null,
      );

      expect(
          paymentCodeAliceV1.notificationAddress(), kNotificationAddressAlice);

      final paymentCodeBobV1 = PaymentCode.fromPaymentCode(
        kPaymentCodeBob,
        null,
      );

      expect(paymentCodeBobV1.notificationAddress(), kNotificationAddressBob);
    });

    test('notification tx', () async {
      final bip32NodeAlice = bip32.BIP32
          .fromSeed(bip39.mnemonicToSeed(kSeedAlice))
          .derivePath(kPath);
      final paymentCodeAliceV1 = PaymentCode.initFromPubKey(
          bip32NodeAlice.publicKey, bip32NodeAlice.chainCode);

      expect(
          paymentCodeAliceV1.getPayload().toHex,
          "010002b85034fb08a8bfefd22848238257b252721454bbbfba2c3667f168837ea2cd"
          "ad671af9f65904632e2dcc0c6ad314e11d53fc82fa4c4ea27a4a14eccecc478fee00"
          "000000000000000000000000");

      final paymentCodeBobV1 = PaymentCode.fromPaymentCode(
        kPaymentCodeBob,
        null,
      );

      final aliceECPair = ECPair.fromWIF(
          "Kx983SRhAZpAhj7Aac1wUXMJ6XZeyJKqCxJJ49dxEbYCT4a1ozRD");

      final txPointData =
          "86f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c"
              .fromHex
              .reversed
              .toList();
      final txPointDataIndex = 1;
      final _rev = txPointData.reversed.toList();
      final rev = Uint8List(_rev.length + 4);
      Util.copyBytes(Uint8List.fromList(_rev), 0, rev, 0, _rev.length);
      final buffer = rev.buffer.asByteData();
      buffer.setUint32(_rev.length, txPointDataIndex, Endian.little);
      expect(
        rev.toHex,
        "86f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c01000000",
      );

      final S = SecretPoint(
          aliceECPair.privateKey!, paymentCodeBobV1.notificationPublicKey());
      expect(
        S.ecdhSecret().toHex,
        "736a25d9250238ad64ed5da03450c6a3f4f8f4dcdf0b58d1ed69029d76ead48d",
      );

      final blindingMask = PaymentCode.getMask(S.ecdhSecret(), rev);
      expect(
        blindingMask.toHex,
        "be6e7a4256cac6f4d4ed4639b8c39c4cb8bece40010908e70d17ea9d77b4dc57f1da36f2d6641ccb37cf2b9f3146686462e0fa3161ae74f88c0afd4e307adbd5",
      );

      final blindedPaymentCode = PaymentCode.blind(
        paymentCodeAliceV1.getPayload(),
        blindingMask,
      );
      expect(
        blindedPaymentCode.toHex,
        "010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b00000000000000000000000000",
      );

      final opReturnScript = bscript.compile([
        0x6a,
        // (OPS["OP_RETURN"] as int),
        blindedPaymentCode,
      ]);
      expect(
        opReturnScript.toHex,
        "6a4c50010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b00000000000000000000000000",
      );

      final bobP2PKH = P2PKH(
        data: PaymentData(
          pubkey: paymentCodeBobV1.notificationPublicKey(),
        ),
      ).data;
      final notificationScript = bscript.compile([bobP2PKH.output]);
      expect(Uint8List.fromList(notificationScript.toList().sublist(1)).toHex,
          "76a9148066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac");

      // build a notification tx
      final txb = TransactionBuilder();
      txb.setVersion(1);

      txb.addInput(
        "9c6000d597c5008f7bfc2618aed5e4a6ae57677aab95078aae708e1cab11f486",
        txPointDataIndex,
      );

      txb.addOutput(paymentCodeBobV1.notificationAddress(), 10000);
      txb.addOutput(opReturnScript, 10000);

      txb.sign(
        vin: 0,
        keyPair: aliceECPair,
      );

      final builtTx = txb.build();

      expect(builtTx.getId(),
          "9414f1681fb1255bd168a806254321a837008dd4480c02226063183deb100204");

      final expectedTxid =
          "010000000186f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c010000006b48304502210"
          "0ac8c6dbc482c79e86c18928a8b364923c774bfdbd852059f6b3778f2319b59a7022029d7cc5724e2f41ab1fcfc0ba5"
          "a0d4f57ca76f72f19530ba97c860c70a6bf0a801210272d83d8a1fa323feab1c085157a0791b46eba34afb8bfbfaeb3"
          "a3fcc3f2c9ad8ffffffff0210270000000000001976a9148066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac1027"
          "000000000000536a4c50010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0c"
          "f048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b0000000000000000000000000000000000";
      expect(builtTx.toHex(), expectedTxid);
    });

    test('Payment code v1 alice send addresses', () async {
      final bip32NodeAlice = bip32.BIP32
          .fromSeed(bip39.mnemonicToSeed(kSeedAlice))
          .derivePath(kPath);

      final paymentCodeBobV1 = PaymentCode.fromPaymentCode(
        kPaymentCodeBob,
        null,
      );

      final a2b = PaymentAddress.initWithPrivateKey(
          bip32NodeAlice.derive(0).privateKey!, paymentCodeBobV1, 0);
      expect(a2b.getSendAddress(), "141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK");

      a2b.index++;
      expect(a2b.getSendAddress(), "12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6");

      a2b.index++;
      expect(a2b.getSendAddress(), "1FsBVhT5dQutGwaPePTYMe5qvYqqjxyftc");
    });

    test('Payment code v1 bob receive addresses', () async {
      final bobBip32 = bip32.BIP32
          .fromSeed(bip39.mnemonicToSeed(kSeedBob))
          .derivePath(kPath);
      final pcodeA = PaymentCode.fromPaymentCode(
        kPaymentCodeAlice,
        null,
      );

      final a2b = PaymentAddress.initWithPrivateKey(
          bobBip32.derive(0).privateKey!, pcodeA, 0);
      expect(a2b.getReceiveAddress(), "141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK");

      final a2b1 = PaymentAddress.initWithPrivateKey(
          bobBip32.derive(1).privateKey!, pcodeA, 0);
      expect(a2b1.getReceiveAddress(), "12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6");

      final a2b2 = PaymentAddress.initWithPrivateKey(
          bobBip32.derive(2).privateKey!, pcodeA, 0);
      expect(a2b2.getReceiveAddress(), "1FsBVhT5dQutGwaPePTYMe5qvYqqjxyftc");
    });
  });
}
