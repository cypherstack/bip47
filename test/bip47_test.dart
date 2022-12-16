import 'package:bip32/bip32.dart';
import 'package:bip39/bip39.dart' as bip39;
import 'package:bip47/src/payment_address.dart';
import 'package:bip47/src/payment_code.dart';
import 'package:bip47/src/payment_code_v3.dart';
import 'package:convert/convert.dart';
// import 'package:pointycastle/pointycastle.dart';
import 'package:test/test.dart';

void main() {
  // final ECDomainParameters CURVE = ECDomainParameters("secp256k1");

  String seedAlice =
      "response seminar brave tip suit recall often sound stick owner lottery motion";
  // String seedBob =
  //     "reward upper indicate eight swift arch injury crystal super wrestle already dentist";

  group("payment code v3", () {
    test('Payment code v3 from xpubstr', () async {
      final accountAlice = BIP32
          .fromSeed(bip39.mnemonicToSeed(seedAlice))
          .derivePath("m/47'/0'/0'");

      final paymentCodeAlice = PaymentCodeV3();
      await paymentCodeAlice
          .initFromXPubStr(accountAlice.neutered().toBase58());

      expect(paymentCodeAlice.toString(),
          "PD1jTsa1rjnbMMLVbj5cg2c8KkFY32KWtPRqVVpSBkv1jf8zjHJVu");
    });

    test('get pub key', () async {
      final bip32bip32NodeAlice =
          BIP32.fromSeed(bip39.mnemonicToSeed(seedAlice));

      final accountAlice = bip32bip32NodeAlice.derivePath("m/47'/0'/0'");

      final paymentCodeAlice = PaymentCodeV3();
      await paymentCodeAlice
          .initFromXPubStr(accountAlice.neutered().toBase58());

      expect(paymentCodeAlice.getPubkey(), accountAlice.publicKey);
    });

    test('Payment code v3 getNotifPrivkey', () async {
      final bip32bip32NodeAlice =
          BIP32.fromSeed(bip39.mnemonicToSeed(seedAlice));

      final accountAlice = bip32bip32NodeAlice.derivePath("m/47'/0'/0'");

      final paymentCodeAlice = PaymentCodeV3();
      await paymentCodeAlice
          .initFromXPubStr(accountAlice.neutered().toBase58());

      paymentCodeAlice.setXprv(accountAlice.toBase58());

      final k = await paymentCodeAlice.getNotifPrivkey();

      String hexK = hex.encode(k!);
      print("hexK: $hexK}");

      expect(hexK,
          "7167db816df3e03b4f4df749dd1c1cf5b9a81ae0ce0b2f4dc5d8b75aea4e77e0");
    });
  });

  group("payment codes v1", () {
    test('Payment code v1 initFromPubKey', () async {
      final bip32NodeAlice = BIP32
          .fromSeed(bip39.mnemonicToSeed(seedAlice))
          .derivePath("m/47'/0'/0'");

      final paymentCodeAliceV1 = PaymentCode();
      await paymentCodeAliceV1.initFromPubKey(
          bip32NodeAlice.publicKey, bip32NodeAlice.chainCode);

      expect(
        paymentCodeAliceV1.toString(),
        "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA",
      );
    });

    test('Payment code v1 initFromPaymentCode', () async {
      final bip32NodeAlice = BIP32
          .fromSeed(bip39.mnemonicToSeed(seedAlice))
          .derivePath("m/47'/0'/0'");

      final paymentCodeAliceV1 = PaymentCode.fromPaymentCode(
        "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA",
        bitcoin,
      );

      expect(paymentCodeAliceV1.getPubKey(), bip32NodeAlice.publicKey);
      expect(paymentCodeAliceV1.getChain(), bip32NodeAlice.chainCode);
    });

    test('Payment code v1 notificationAddress', () async {
      final paymentCodeAliceV1 = PaymentCode.fromPaymentCode(
        "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA",
        bitcoin,
      );

      expect(paymentCodeAliceV1.notificationAddress(),
          "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW");
    });
  });

  group("payment address", () {
    test('Ay', () async {
      final bip32NodeAlice = BIP32
          .fromSeed(bip39.mnemonicToSeed(seedAlice))
          .derivePath("m/47'/0'/0'");

      final paymentCodeAliceV1 = PaymentCode();
      await paymentCodeAliceV1.initFromPubKey(
          bip32NodeAlice.publicKey, bip32NodeAlice.chainCode);

      final pa = PaymentAddress();
      pa.initWith(bip32NodeAlice.privateKey!, paymentCodeAliceV1, 0);

      print("rcv  address: ${await pa.getReceiveAddress()}");
      print("send address: ${await pa.getSendAddress()}");
    });
  });
}
