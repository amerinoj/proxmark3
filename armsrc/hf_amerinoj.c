//-----------------------------------------------------------------------------
// Alberto Merino, 2021
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for hf_amerinoj by Alberto Merino
//-----------------------------------------------------------------------------
/*

hf_amerinoj` has two functions :
	First: Read the block0 from a original mifare card and them copy the block into a Chinise card
	Second:	Emule a blank Mifare card with the original block 0.

*/
#include "standalone.h"
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "ticks.h"
#include "string.h"
#include "BigBuf.h"
#include "iso14443a.h"
#include "protocols.h"
#include "mifarecmd.h"
#include "mifaresim.h"
#include "mifareutil.h"
#define STATE_READ 0
#define STATE_EMUL 1
#define STATE_CLONE 2
#define BLOCK_SIZE_1K 63
#define BLOCK_SIZE_2K 127
#define BLOCK_SIZE_4K 255


static void  mfELoadDummy(uint8_t *blk0, int Bsize) {
    uint8_t block0[16] = {0x01, 0x02, 0x03, 0x04, 0x04, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xAF};
    uint8_t blockD[16] = {0x00};
    uint8_t blockK[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x08, 0x77, 0x8F, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    if (blk0 != NULL) {
        memcpy(block0, blk0, 16);
    }
	
    DbpString("Loading Emulation Memory");
    for (int blockNo = 0; blockNo < Bsize +1; blockNo++) {
            if (blockNo == 0) {
				emlSetMem(block0, blockNo, 1); 
            } else {
				
                if (IsSectorTrailer(blockNo)){
					emlSetMem(blockK, blockNo, 1);			
				}
                else{
					emlSetMem(blockD, blockNo, 1);						
				}
            }
    }
}

static int saMifareCIdent(bool is_mfc) {
    // variables
	static uint8_t wupC1[] = { MIFARE_MAGICWUPC1 };
	static uint8_t wupC2[] = { MIFARE_MAGICWUPC2 };
    uint8_t isGen = 0;
    uint8_t rec[1] = {0x00};
    uint8_t recpar[1] = {0x00};
    uint8_t rats[4] = { ISO14443A_CMD_RATS, 0x80, 0x31, 0x73 };
    uint8_t rdblf0[4] = { ISO14443A_CMD_READBLOCK, 0xF0, 0x8D, 0x5f};
    uint8_t rdbl00[4] = { ISO14443A_CMD_READBLOCK, 0x00, 0x02, 0xa8};
    uint8_t *par = BigBuf_malloc(MAX_PARITY_SIZE);
    uint8_t *buf = BigBuf_malloc(PM3_CMD_DATA_SIZE);
    uint8_t *uid = BigBuf_malloc(10);

    memset(par, 0x00, MAX_PARITY_SIZE);
    memset(buf, 0x00, PM3_CMD_DATA_SIZE);
    memset(uid, 0x00, 10);

    uint32_t cuid = 0;
 

    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

    // Generation 1 test
    ReaderTransmitBitsPar(wupC1, 7, NULL, NULL);
    if (ReaderReceive(rec, recpar) && (rec[0] == 0x0a)) {
        ReaderTransmit(wupC2, sizeof(wupC2), NULL);
        if (!ReaderReceive(rec, recpar) || (rec[0] != 0x0a)) {
            isGen = MAGIC_GEN_1B;
            goto OUT;
        };
        isGen = MAGIC_GEN_1A;
        goto OUT;
    }

    // reset card
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    SpinDelay(40);
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

    int res = iso14443a_select_card(uid, NULL, &cuid, true, 0, true);
    if (res == 2) {
        if (cuid == 0xAA55C396) {
            isGen = MAGIC_GEN_UNFUSED;
            goto OUT;
        }

        ReaderTransmit(rats, sizeof(rats), NULL);
        res = ReaderReceive(buf, par);
        if (res) {
            // test for some MFC gen2
            if (memcmp(buf, "\x09\x78\x00\x91\x02\xDA\xBC\x19\x10\xF0\x05", 11) == 0) {

                // super card ident
                uint8_t super[] = {0x0A, 0x00, 0x00, 0xA6, 0xB0, 0x00, 0x10, 0x14, 0x1D};
                ReaderTransmit(super, sizeof(super), NULL);
                res = ReaderReceive(buf, par);
                if (res == 22) {
                    isGen = MAGIC_SUPER;
                    goto OUT;
                }

                isGen = MAGIC_GEN_2;
                goto OUT;
            }

			
            // test for some MFC 7b gen2
            if (memcmp(buf, "\x0D\x78\x00\x71\x02\x88\x49\xA1\x30\x20\x15\x06\x08\x56\x3D", 15) == 0) {
                isGen = MAGIC_GEN_2;
                goto OUT;
            }
            // test for Ultralight magic gen2
            if (memcmp(buf, "\x0A\x78\x00\x81\x02\xDB\xA0\xC1\x19\x40\x2A\xB5", 12) == 0) {
                isGen = MAGIC_GEN_2;
                goto OUT;
            }
            // test for Ultralight EV1 magic gen2
            if (memcmp(buf, "\x85\x00\x00\xA0\x00\x00\x0A\xC3\x00\x04\x03\x01\x01\x00\x0B\x03\x41\xDF", 18) == 0) {
                isGen = MAGIC_GEN_2;
                goto OUT;
            }
            // test for some other Ultralight EV1 magic gen2
            if (memcmp(buf, "\x85\x00\x00\xA0\x0A\x00\x0A\xC3\x00\x04\x03\x01\x01\x00\x0B\x03\x16\xD7", 18) == 0) {
                isGen = MAGIC_GEN_2;
                goto OUT;
            }
            // test for some other Ultralight magic gen2
            if (memcmp(buf, "\x85\x00\x00\xA0\x0A\x00\x0A\xB0\x00\x00\x00\x00\x00\x00\x00\x00\x18\x4D", 18) == 0) {
                isGen = MAGIC_GEN_2;
                goto OUT;
            }
            // test for NTAG213 magic gen2
            if (memcmp(buf, "\x85\x00\x00\xA0\x00\x00\x0A\xA5\x00\x04\x04\x02\x01\x00\x0F\x03\x79\x0C", 18) == 0) {
                isGen = MAGIC_GEN_2;
                goto OUT;
            }
        }

        if (is_mfc == false) {
            // magic ntag test
            FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
            SpinDelay(40);
            iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
            res = iso14443a_select_card(uid, NULL, &cuid, true, 0, true);
            if (res == 2) {
                ReaderTransmit(rdblf0, sizeof(rdblf0), NULL);
                res = ReaderReceive(buf, par);
                if (res == 18) {
                    isGen = MAGIC_NTAG21X;
                }
            }
        } else {
            // magic MFC Gen3 test
            FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
            SpinDelay(40);
            iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
            res = iso14443a_select_card(uid, NULL, &cuid, true, 0, true);
            if (res == 2) {
                ReaderTransmit(rdbl00, sizeof(rdbl00), NULL);
                res = ReaderReceive(buf, par);
                if (res == 18) {
                    isGen = MAGIC_GEN_3;
                }
            }
        }
    };

OUT:
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
			Dbprintf("GEN: i% ", isGen);
			DbpString("RATS RESPONSE 2");
			Dbhexdump(18, buf, 0);
    return isGen;
}
	
void ModInfo(void) {
    DbpString("HF AMERINOJ mode - copy and emulates Mifare Block0 (UID+BCC+ATQA+MFD");
}

void RunMod(void) {
    StandAloneMode();
    Dbprintf(_YELLOW_("HF AMERINOJ mode started"));
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	
    iso14a_card_select_t card , m_card;
	int state = STATE_READ;
	uint8_t block0[16] = {0x00}, testblock0[16] = {0};
	uint64_t mfKeys[] = {
        0xffffffffffff, // Default key
        0x000000000000, // Blank key
	};
	uint32_t cuid = 0 , m_cuid = 0;
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;	
	pcs = &mpcs;
		

    // the main loop for your standalone mode
    for (;;) {
        WDT_HIT();
        // exit from RunMod,   send a usbcommand.
        if (data_available()) break;

        SpinDelay(500);
        // 0 = search, 1 = read, 2 = emul
        state = STATE_READ;
		LED_A_OFF();
		LED_B_OFF();
		LED_C_OFF();
		LED_D_OFF();
        DbpString("Scanning...");
        int button_pressed = BUTTON_NO_CLICK;
        for (;;) {
            // Was our button held down or pressed?
            button_pressed = BUTTON_HELD(1000);
            if (button_pressed != BUTTON_NO_CLICK || data_available())
                break;
            else if (state == STATE_READ) {
                iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);
                if (iso14443a_select_card(NULL, &card, &cuid, true, 0, true) == false) {
                    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
                    LED_D_OFF();
                    SpinDelay(500);
                    continue;
                } else {
					
					mifare_classic_auth(pcs, cuid, 0, AUTHKEYA, mfKeys[0], AUTH_FIRST);
					mifare_classic_readblock(pcs, cuid, 0, block0);
					
					if (block0[0] != 0x00 || block0[1] != 0x00 || block0[2] != 0x00 || block0[3] != 0x00) {

						Dbprintf("Found card with SAK: %02X, ATQA: %02X %02X, UID: ", card.sak, card.atqa[0], card.atqa[1]);
						Dbhexdump(card.uidlen, card.uid, 0);
						DbpString("Block0:");
						Dbhexdump(16, block0, 0);
						 
						state = STATE_CLONE;
					}
                }
            } else if (state == STATE_CLONE) {
						DbpString("Waiting 20s Magic CARD to Clone Block0");
						int count = 0;
						int Cident = 0;
						while ( Cident == 0 ){
							Cident=saMifareCIdent(false);
							SpinDelay(500);
							LED_B_ON();
							SpinDelay(500);
							LED_B_OFF();
							count++;
							if (count >= 20) {
								DbpString("Time expired");
								break;
							}
						
						};
						
						if ( Cident != 0 ){

							iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);
							MifareCGetBlock(MAGIC_SINGLE, 0, testblock0);
							SpinDelay(500);
							MifareCSetBlock(MAGIC_SINGLE, 0, block0);
							iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);
							while ( iso14443a_select_card(NULL, &m_card, &m_cuid, true, 0, true) == false) {
									FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
									SpinDelay(500);
							}
							mifare_classic_auth(pcs, m_cuid, 0, AUTHKEYA, mfKeys[0], AUTH_FIRST);
							mifare_classic_readblock(pcs, m_cuid, 0, testblock0);
							if (memcmp(testblock0, block0, 16) == 0) {
								DbpString("Cloned successful!");
								LED_A_ON();
                    
							} else {
								DbpString("Clone failed");
								LED_D_ON();
							}
						
							DbpString("Magic Card Block0:");
							Dbhexdump(16, testblock0, 0);					
						}
						

			state = STATE_EMUL;
			}
			else if (state == STATE_EMUL) {
                uint8_t flags = 0;
                if (card.uidlen == 4) {
                    flags |= FLAG_4B_UID_IN_DATA;
                } else if (card.uidlen == 7) {
                    flags |= FLAG_7B_UID_IN_DATA;
                } else if (card.uidlen == 10) {
                    flags |= FLAG_10B_UID_IN_DATA;
                } else {
                    DbpString("Unusual UID length, something is wrong. Try again please.");
                    state = STATE_READ;
                    continue;
                }


				DbpString("Emulating");
				uint16_t simflags = FLAG_UID_IN_EMUL ;		
                DbpString("Starting simulation, press pm3-button to stop and go back to search state.");

                    if (card.sak == 0x08 && card.atqa[0] == 0x04 && card.atqa[1] == 0) {
                        DbpString("Mifare Classic 1k");	
						mfELoadDummy(block0,BLOCK_SIZE_1K);
						simflags = simflags | FLAG_MF_1K;
						Mifare1ksim(simflags, 0, card.uid, 0, 0);
                    } else if (card.sak == 0x18 && card.atqa[0] == 0x02 && card.atqa[1] == 0) {
                        DbpString("Mifare Classic 4k");
						mfELoadDummy(block0,BLOCK_SIZE_4K);
						simflags = simflags | FLAG_MF_4K ;
						Mifare1ksim(simflags, 0, card.uid, 0, 0);
                    } else if (card.sak == 0x00 && card.atqa[0] == 0x44 && card.atqa[1] == 0) {
                        DbpString("Mifare Ultralight");
                        SimulateIso14443aTag(2, flags, card.uid, 0);
                    } else if (card.sak == 0x20 && card.atqa[0] == 0x04 && card.atqa[1] == 0x03) {
                        DbpString("Mifare DESFire");
                        SimulateIso14443aTag(3, flags, card.uid, 0);
                    } else {
                        DbpString("Unrecognized tag type -- defaulting to Mifare Classic emulation");
                        SimulateIso14443aTag(1, flags, card.uid, 0);
                    }                

                // Go back to search state if user presses pm3-button
                state = STATE_READ;
            }
        }
        if (button_pressed  == BUTTON_HOLD)        //Holding down the button
            break;
    }

    Dbprintf("-=[ exit ]=-");
    LEDsoff();
}
