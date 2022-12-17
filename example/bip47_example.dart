import 'package:bip32/bip32.dart';
import 'package:bip39/bip39.dart' as bip39;
import 'package:bip47/bip47.dart';

void main() async {
  String seedAlice =
      "response seminar brave tip suit recall often sound stick owner lottery motion";

  // bip32 hd node
  final node =
      BIP32.fromSeed(bip39.mnemonicToSeed(seedAlice)).derivePath("m/47'/0'/0'");

  // create code
  final paymentCode = PaymentCode();

  // initialize from bip32 node pubkey and chaincode
  await paymentCode.initFromPubKey(
    node.publicKey,
    node.chainCode,
  );

  print("payment code: $paymentCode");
}
