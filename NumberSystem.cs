using System;
using System.Collections.Generic;
using System.Text;

namespace CDiChain.EncodingCryption
{
    public enum NumberSystem
    {
        /// <summary>
        /// 8进制, 0~8
        /// </summary>
        N8,

        /// <summary>
        /// 十进制
        /// </summary>
        N10,

        /// <summary>
        /// 16进制
        /// </summary>
        N16,

        /// <summary>
        /// 26进制, 全大写字母,A-Z, 兼容MySQL OrderBy, URL安全
        /// </summary>
        N26,

        /// <summary>
        /// 36进制, 0-9&全大写字母A-Z, 兼容MySQL OrderBy, URL安全
        /// </summary>
        N36,

        /// <summary>
        /// 42进制, 0-9,A-Z, 6个URL安全的标点符号, 兼容MySQL OrderBy, URL安全
        /// </summary>
        N42,

        /// <summary>
        /// 62进制, 0-9,a-z,A-Z, URL安全, 不兼容MySql
        /// </summary>
        N62,

        /// <summary>
        /// Base64编码
        /// </summary>
        Base64,

        /// <summary>
        /// URL安全的Base64编码
        /// </summary>
        SafeBase64,

        /// <summary>
        /// 68进制, 0-9a-zA-Z加6个URL安全字符, URL安全, MySql不兼容
        /// </summary>
        N68
    }
}
