﻿using Org.BouncyCastle.Extended.Math;

namespace Org.BouncyCastle.Extended.Crypto.Agreement.JPake
{
    /// <summary>
    /// Standard pre-computed prime order groups for use by J-PAKE.
    /// (J-PAKE can use pre-computed prime order groups, same as DSA and Diffie-Hellman.)
    /// <p/>
    /// This class contains some convenient constants for use as input for
    /// constructing {@link JPAKEParticipant}s.
    /// <p/>
    /// The prime order groups below are taken from Sun's JDK JavaDoc (docs/guide/security/CryptoSpec.html#AppB),
    /// and from the prime order groups
    /// <a href="http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/DSA2_All.pdf">published by NIST</a>.
    /// </summary>
    public class JPakePrimeOrderGroups
    {
        /// <summary>
        /// From Sun's JDK JavaDoc (docs/guide/security/CryptoSpec.html#AppB)
        /// 1024-bit p, 160-bit q and 1024-bit g for 80-bit security.
        /// </summary>
        public static readonly JPakePrimeOrderGroup SUN_JCE_1024 = new JPakePrimeOrderGroup(
            // p
            new BigInteger(
                "fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669" +
                    "455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b7" +
                    "6b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb" +
                    "83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7", 16),
            // q
            new BigInteger("9760508f15230bccb292b982a2eb840bf0581cf5", 16),
            // g
            new BigInteger(
                "f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d078267" +
                    "5159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e1" +
                    "3c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243b" +
                    "cca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a", 16),
            true
        );

        /// <summary>
        /// From NIST.
        /// 2048-bit p, 224-bit q and 2048-bit g for 112-bit security.
        /// </summary>
        public static readonly JPakePrimeOrderGroup NIST_2048 = new JPakePrimeOrderGroup(
            // p
            new BigInteger(
                "C196BA05AC29E1F9C3C72D56DFFC6154A033F1477AC88EC37F09BE6C5BB95F51" +
                    "C296DD20D1A28A067CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE4" +
                    "28782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE619ECACC7E0B51652" +
                    "A8776D02A425567DED36EABD90CA33A1E8D988F0BBB92D02D1D20290113BB562" +
                    "CE1FC856EEB7CDD92D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BF" +
                    "FAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E5320121496DC65B3" +
                    "930E38047294FF877831A16D5228418DE8AB275D7D75651CEFED65F78AFC3EA7" +
                    "FE4D79B35F62A0402A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83", 16),
            // q
            new BigInteger("90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D", 16),
            // g
            new BigInteger(
                "A59A749A11242C58C894E9E5A91804E8FA0AC64B56288F8D47D51B1EDC4D6544" +
                    "4FECA0111D78F35FC9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E50" +
                    "48B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B6E770409494B7FEE" +
                    "1DBB1E4B2BC2A53D4F893D418B7159592E4FFFDF6969E91D770DAEBD0B5CB14C" +
                    "00AD68EC7DC1E5745EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDF" +
                    "D049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E695515B05BD412F5B8" +
                    "C2F4C77EE10DA48ABD53F5DD498927EE7B692BBBCDA2FB23A516C5B4533D7398" +
                    "0B2A3B60E384ED200AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085", 16),
            true
        );

        /// <summary>
        /// From NIST.
        /// 3072-bit p, 256-bit q and 3072-bit g for 128-bit security.
        /// </summary>
        public static readonly JPakePrimeOrderGroup NIST_3072 = new JPakePrimeOrderGroup(
            // p
            new BigInteger(
                "90066455B5CFC38F9CAA4A48B4281F292C260FEEF01FD61037E56258A7795A1C" +
                    "7AD46076982CE6BB956936C6AB4DCFE05E6784586940CA544B9B2140E1EB523F" +
                    "009D20A7E7880E4E5BFA690F1B9004A27811CD9904AF70420EEFD6EA11EF7DA1" +
                    "29F58835FF56B89FAA637BC9AC2EFAAB903402229F491D8D3485261CD068699B" +
                    "6BA58A1DDBBEF6DB51E8FE34E8A78E542D7BA351C21EA8D8F1D29F5D5D159394" +
                    "87E27F4416B0CA632C59EFD1B1EB66511A5A0FBF615B766C5862D0BD8A3FE7A0" +
                    "E0DA0FB2FE1FCB19E8F9996A8EA0FCCDE538175238FC8B0EE6F29AF7F642773E" +
                    "BE8CD5402415A01451A840476B2FCEB0E388D30D4B376C37FE401C2A2C2F941D" +
                    "AD179C540C1C8CE030D460C4D983BE9AB0B20F69144C1AE13F9383EA1C08504F" +
                    "B0BF321503EFE43488310DD8DC77EC5B8349B8BFE97C2C560EA878DE87C11E3D" +
                    "597F1FEA742D73EEC7F37BE43949EF1A0D15C3F3E3FC0A8335617055AC91328E" +
                    "C22B50FC15B941D3D1624CD88BC25F3E941FDDC6200689581BFEC416B4B2CB73", 16),
            // q
            new BigInteger("CFA0478A54717B08CE64805B76E5B14249A77A4838469DF7F7DC987EFCCFB11D", 16),
            // g
            new BigInteger(
                "5E5CBA992E0A680D885EB903AEA78E4A45A469103D448EDE3B7ACCC54D521E37" +
                    "F84A4BDD5B06B0970CC2D2BBB715F7B82846F9A0C393914C792E6A923E2117AB" +
                    "805276A975AADB5261D91673EA9AAFFEECBFA6183DFCB5D3B7332AA19275AFA1" +
                    "F8EC0B60FB6F66CC23AE4870791D5982AAD1AA9485FD8F4A60126FEB2CF05DB8" +
                    "A7F0F09B3397F3937F2E90B9E5B9C9B6EFEF642BC48351C46FB171B9BFA9EF17" +
                    "A961CE96C7E7A7CC3D3D03DFAD1078BA21DA425198F07D2481622BCE45969D9C" +
                    "4D6063D72AB7A0F08B2F49A7CC6AF335E08C4720E31476B67299E231F8BD90B3" +
                    "9AC3AE3BE0C6B6CACEF8289A2E2873D58E51E029CAFBD55E6841489AB66B5B4B" +
                    "9BA6E2F784660896AFF387D92844CCB8B69475496DE19DA2E58259B090489AC8" +
                    "E62363CDF82CFD8EF2A427ABCD65750B506F56DDE3B988567A88126B914D7828" +
                    "E2B63A6D7ED0747EC59E0E0A23CE7D8A74C1D2C2A7AFB6A29799620F00E11C33" +
                    "787F7DED3B30E1A22D09F1FBDA1ABBBFBF25CAE05A13F812E34563F99410E73B", 16),
            true
        );
    }
}
