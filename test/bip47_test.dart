import 'package:bip32/bip32.dart';
import 'package:bip39/bip39.dart' as bip39;
import 'package:bip47/src/payment_address.dart';
import 'package:bip47/src/payment_code.dart';
// import 'package:pointycastle/pointycastle.dart';
import 'package:test/test.dart';

// test data chosen from https://github.com/SamouraiDev/OBPPrfc05/blob/main/TestVectorsV3.java
// and https://github.com/rust-bitcoin/rust-bip47/blob/master/src/lib.rs#L718-L720

void main() {
  String seedAlice =
      "response seminar brave tip suit recall often sound stick owner lottery motion";

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
}
