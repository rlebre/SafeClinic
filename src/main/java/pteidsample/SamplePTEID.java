package pteidsample;

import pt.gov.cartaodecidadao.*;

public class SamplePTEID {
    static {
        try {
            System.loadLibrary("pteidlibj");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load. \n" + e);
            System.exit(1);
        }
    }

    public static void main(String[] args) {
        try {
            PTEID_ReaderSet.initSDK();

            PTEID_EIDCard card;
            PTEID_ReaderContext context;
            PTEID_ReaderSet readerSet;
            readerSet = PTEID_ReaderSet.instance();

            for (int i = 0; i < readerSet.readerCount(); i++) {
                context = readerSet.getReaderByNum(i);
                if (context.isCardPresent()) {
                    card = context.getEIDCard();

                }

                if (context.isCardPresent()) {
                    card = context.getEIDCard();


                    PTEID_ulwrapper triesLeft = new PTEID_ulwrapper(-1);
                    PTEID_Address address;
                    PTEID_Pins pins = card.getPins();
                    PTEID_Pin pin = pins.getPinByPinRef(PTEID_Pin.ADDR_PIN);
                    if (pin.verifyPin("", triesLeft, true)) {
                        address = card.getAddr();
                        String countryCode = address.getCountryCode();
                        String district = address.getDistrict();
                        String municipality = address.getMunicipality();
                        String street = address.getStreetName();

                        System.out.println(district);

                    }

                    PTEID_Certificate signature = card.getAuthentication();
                    if (signature.isFromPteidValidChain()) {
                    } else {

                        System.out.println("Not VALID");
                    }
                }
            }
        } catch (PTEID_Exception e) {
            e.printStackTrace();
        } finally {
            try {
                PTEID_ReaderSet.releaseSDK();
            } catch (PTEID_Exception e) {
                e.printStackTrace();
            }
        }

    }
}