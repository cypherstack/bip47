import 'package:bip32/bip32.dart' as bip32;
import 'package:bip39/bip39.dart' as bip39;
import 'package:bip47/bip47.dart';
import 'package:test/test.dart';

const String kPath = "m/47'/0'/0'";

// following test data chosen from:
// https://gist.github.com/SamouraiDev/6aad669604c5930864bd
// https://github.com/SamouraiDev/OBPPrfc05/blob/main/TestVectorsV3.java
// https://github.com/rust-bitcoin/rust-bip47/blob/master/src/lib.rs#L718-L720
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

      final paymentCodeAliceV1 = PaymentCode();
      await paymentCodeAliceV1.initFromPubKey(
          bip32NodeAlice.publicKey, bip32NodeAlice.chainCode);

      expect(
        paymentCodeAliceV1.toString(),
        kPaymentCodeAlice,
      );

      final bip32NodeBob = bip32.BIP32
          .fromSeed(bip39.mnemonicToSeed(kSeedBob))
          .derivePath(kPath);

      final paymentCodeBobV1 = PaymentCode();
      await paymentCodeBobV1.initFromPubKey(
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
  });
}
