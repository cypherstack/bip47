import 'package:bip32/bip32.dart' as bip32;
import 'package:bip39/bip39.dart' as bip39;
import 'package:bip47/bip47.dart';
import 'package:bitcoindart/bitcoindart.dart' as bitcoindart;
import 'package:test/test.dart';

const String kPath = "m/47'/0'/0'";

const String kSeedAlice =
    "response seminar brave tip suit recall often sound stick owner lottery mot"
    "ion";
const String kSeedBob =
    "reward upper indicate eight swift arch injury crystal super wrestle alread"
    "y dentist";

bip32.NetworkType get btcNetwork => bip32.NetworkType(
      wif: bitcoindart.bitcoin.wif,
      bip32: bip32.Bip32Type(
        public: bitcoindart.bitcoin.bip32.public,
        private: bitcoindart.bitcoin.bip32.private,
      ),
    );

void main() {
  late bip32.BIP32 aliceNode;
  late bip32.BIP32 bobNode;

  setUpAll(() {
    final aliceSeed = bip39.mnemonicToSeed(kSeedAlice);
    final aliceRoot = bip32.BIP32.fromSeed(aliceSeed, btcNetwork);
    aliceNode = aliceRoot.derivePath(kPath);

    final bobSeed = bip39.mnemonicToSeed(kSeedBob);
    final bobRoot = bip32.BIP32.fromSeed(bobSeed, btcNetwork);
    bobNode = bobRoot.derivePath(kPath);
  });

  group('PaymentCode taproot feature bit', () {
    test('fromBip32Node with shouldSetTaprootBit sets both bits', () {
      final code = PaymentCode.fromBip32Node(
        aliceNode,
        networkType: bitcoindart.bitcoin,
        shouldSetSegwitBit: true,
        shouldSetTaprootBit: true,
      );
      expect(code.isTaprootEnabled(), isTrue);
      expect(code.isSegWitEnabled(), isTrue);
    });

    test('fromBip32Node without taproot does not set taproot bit', () {
      final code = PaymentCode.fromBip32Node(
        aliceNode,
        networkType: bitcoindart.bitcoin,
        shouldSetSegwitBit: true,
      );
      expect(code.isTaprootEnabled(), isFalse);
      expect(code.isSegWitEnabled(), isTrue);
    });

    test('fromBip32Node with neither flag sets neither bit', () {
      final code = PaymentCode.fromBip32Node(
        aliceNode,
        networkType: bitcoindart.bitcoin,
        shouldSetSegwitBit: false,
      );
      expect(code.isTaprootEnabled(), isFalse);
      expect(code.isSegWitEnabled(), isFalse);
    });

    test('round-trip: encode taproot code, parse back, verify bits', () {
      final original = PaymentCode.fromBip32Node(
        aliceNode,
        networkType: bitcoindart.bitcoin,
        shouldSetSegwitBit: true,
        shouldSetTaprootBit: true,
      );
      final codeString = original.toString();

      final parsed = PaymentCode.fromPaymentCode(
        codeString,
        networkType: bitcoindart.bitcoin,
      );
      expect(parsed.isTaprootEnabled(), isTrue);
      expect(parsed.isSegWitEnabled(), isTrue);
    });

    test('round-trip: segwit-only code preserved', () {
      final original = PaymentCode.fromBip32Node(
        aliceNode,
        networkType: bitcoindart.bitcoin,
        shouldSetSegwitBit: true,
      );
      final parsed = PaymentCode.fromPaymentCode(
        original.toString(),
        networkType: bitcoindart.bitcoin,
      );
      expect(parsed.isSegWitEnabled(), isTrue);
      expect(parsed.isTaprootEnabled(), isFalse);
    });

    test('taproot and non-taproot codes have same notification address', () {
      final taproot = PaymentCode.fromBip32Node(
        aliceNode,
        networkType: bitcoindart.bitcoin,
        shouldSetSegwitBit: true,
        shouldSetTaprootBit: true,
      );
      final v1 = PaymentCode.fromBip32Node(
        aliceNode,
        networkType: bitcoindart.bitcoin,
        shouldSetSegwitBit: false,
      );
      expect(
        taproot.notificationAddressP2PKH(),
        equals(v1.notificationAddressP2PKH()),
      );
    });
  });

  group('PaymentAddress derived public keys', () {
    test('getDerivedSendPublicKey returns 33-byte compressed key', () {
      final bobCode = PaymentCode.fromBip32Node(
        bobNode,
        networkType: bitcoindart.bitcoin,
        shouldSetSegwitBit: false,
      );

      final paymentAddress = PaymentAddress(
        bip32Node: aliceNode.derive(0),
        paymentCode: bobCode,
        networkType: bitcoindart.bitcoin,
        index: 0,
      );

      final pubKey = paymentAddress.getDerivedSendPublicKey();
      expect(pubKey.length, equals(33));
      expect(pubKey[0] == 0x02 || pubKey[0] == 0x03, isTrue);
    });

    test(
        'send and receive derive same public key '
        '(Alice sends to Bob, Bob receives from Alice)', () {
      final aliceCode = PaymentCode.fromBip32Node(
        aliceNode,
        networkType: bitcoindart.bitcoin,
        shouldSetSegwitBit: false,
      );
      final bobCode = PaymentCode.fromBip32Node(
        bobNode,
        networkType: bitcoindart.bitcoin,
        shouldSetSegwitBit: false,
      );

      // Alice sends to Bob: uses Alice's private key + Bob's public code
      final aliceSendAddr = PaymentAddress(
        bip32Node: aliceNode.derive(0),
        paymentCode: bobCode,
        networkType: bitcoindart.bitcoin,
        index: 0,
      );

      // Bob receives from Alice: uses Bob's private key + Alice's public code
      final bobReceiveAddr = PaymentAddress(
        bip32Node: bobNode.derive(0),
        paymentCode: aliceCode,
        networkType: bitcoindart.bitcoin,
        index: 0,
      );

      final sendPubKey = aliceSendAddr.getDerivedSendPublicKey();
      final receivePubKey = bobReceiveAddr.getDerivedReceivePublicKey();

      expect(sendPubKey, equals(receivePubKey));
    });

    test('getDerivedSendPublicKey matches P2PKH address derivation', () {
      final bobCode = PaymentCode.fromBip32Node(
        bobNode,
        networkType: bitcoindart.bitcoin,
        shouldSetSegwitBit: false,
      );

      final paymentAddress = PaymentAddress(
        bip32Node: aliceNode.derive(0),
        paymentCode: bobCode,
        networkType: bitcoindart.bitcoin,
        index: 0,
      );

      // The P2PKH address should correspond to the derived public key
      final p2pkhAddress = paymentAddress.getSendAddressP2PKH();
      final derivedPubKey = paymentAddress.getDerivedSendPublicKey();

      // Verify by constructing P2PKH from the derived key directly
      final pair = bitcoindart.ECPair.fromPublicKey(
        derivedPubKey,
        network: bitcoindart.bitcoin,
      );
      final p2pkh = bitcoindart.P2PKH(
        data: bitcoindart.PaymentData(pubkey: pair.publicKey),
        network: bitcoindart.bitcoin,
      );

      expect(p2pkh.data.address, equals(p2pkhAddress));
    });

    test('derived keys at different indices produce different addresses', () {
      final bobCode = PaymentCode.fromBip32Node(
        bobNode,
        networkType: bitcoindart.bitcoin,
        shouldSetSegwitBit: false,
      );

      final addr0 = PaymentAddress(
        bip32Node: aliceNode.derive(0),
        paymentCode: bobCode,
        networkType: bitcoindart.bitcoin,
        index: 0,
      );
      final addr1 = PaymentAddress(
        bip32Node: aliceNode.derive(0),
        paymentCode: bobCode,
        networkType: bitcoindart.bitcoin,
        index: 1,
      );

      expect(
        addr0.getDerivedSendPublicKey(),
        isNot(equals(addr1.getDerivedSendPublicKey())),
      );
    });
  });
}
