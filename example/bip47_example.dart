import 'package:bip32/bip32.dart';
import 'package:bip39/bip39.dart' as bip39;
import 'package:bip47/bip47.dart';
import 'package:bitcoindart/bitcoindart.dart';

void main() async {
  String seedAlice =
      "response seminar brave tip suit recall often sound stick owner lottery motion";

  // bip32 hd node
  final node =
      BIP32.fromSeed(bip39.mnemonicToSeed(seedAlice)).derivePath("m/47'/0'/0'");

  // initialize from bip32 node pubkey and chaincode
  final paymentCode = PaymentCode.fromBip32Node(
    node,
    networkType: bitcoin,
    shouldSetSegwitBit: false,
  );

  print("payment code: $paymentCode");
}
