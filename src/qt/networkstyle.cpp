// Copyright (c) 2014-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/networkstyle.h>

#include <qt/guiconstants.h>

#include <tinyformat.h>
#include <util/chaintype.h>

#include <QApplication>

static const struct {
    const ChainType networkId;
    const char *appName;
    const int iconColorHueShift;
    const int iconColorSaturationReduction;
} network_styles[] = {
    // !SCASH
    {ChainType::SCASHMAIN, QAPP_APP_NAME_DEFAULT, 0, 0},
    {ChainType::SCASHTESTNET, QAPP_APP_NAME_SCASH_TESTNET, 180, 30},
    {ChainType::SCASHREGTEST, QAPP_APP_NAME_SCASH_REGTEST, 80, 30},
    {ChainType::MAIN, QAPP_APP_NAME_BTC, 0, 0},
    // !SCASH END
    {ChainType::TESTNET, QAPP_APP_NAME_TESTNET, 70, 30},
    {ChainType::SIGNET, QAPP_APP_NAME_SIGNET, 35, 15},
    {ChainType::REGTEST, QAPP_APP_NAME_REGTEST, 160, 30},
};

// titleAddText needs to be const char* for tr()
NetworkStyle::NetworkStyle(const QString &_appName, const int iconColorHueShift, const int iconColorSaturationReduction, const char *_titleAddText):
    appName(_appName),
    titleAddText(qApp->translate("SplashScreen", _titleAddText))
{
    // load pixmap
    QPixmap pixmap(":/icons/bitcoin");

    if(iconColorHueShift != 0 && iconColorSaturationReduction != 0)
    {
        // generate QImage from QPixmap
        QImage img = pixmap.toImage();

        int h,s,l,a;

        // traverse though lines
        for(int y=0;y<img.height();y++)
        {
            QRgb *scL = reinterpret_cast< QRgb *>( img.scanLine( y ) );

            // loop through pixels
            for(int x=0;x<img.width();x++)
            {
                // preserve alpha because QColor::getHsl doesn't return the alpha value
                a = qAlpha(scL[x]);
                QColor col(scL[x]);

                // get hue value
                col.getHsl(&h,&s,&l);

                // rotate color on RGB color circle
                // 70° should end up with the typical "testnet" green
                h+=iconColorHueShift;

                // change saturation value
                if(s>iconColorSaturationReduction)
                {
                    s -= iconColorSaturationReduction;
                }
                col.setHsl(h,s,l,a);

                // set the pixel
                scL[x] = col.rgba();
            }
        }

        //convert back to QPixmap
        pixmap.convertFromImage(img);
    }

    appIcon             = QIcon(pixmap);
    trayAndWindowIcon   = QIcon(pixmap.scaled(QSize(256,256)));
}

const NetworkStyle* NetworkStyle::instantiate(const ChainType networkId)
{
    // !SCASH
    std::string titleAddText = networkId == ChainType::SCASHMAIN ? "" : strprintf("[%s]", ChainTypeToString(networkId));
    // !SCASH END
    for (const auto& network_style : network_styles) {
        if (networkId == network_style.networkId) {
            return new NetworkStyle(
                    network_style.appName,
                    network_style.iconColorHueShift,
                    network_style.iconColorSaturationReduction,
                    titleAddText.c_str());
        }
    }
    return nullptr;
}
