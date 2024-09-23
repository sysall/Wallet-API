let utilityFn = {
    changeToBigString: async function changeToBigString(no) {
        try {
            let ans = no;
            // console.log('no',no)
            let original = no;
            no = no.toString();
            if (no.includes("e")) {
                no = no.split("e");
                if (no.length > 1) {
                    afterDecimal = null;
                    // console.log('no',no)
                    let no1 = no[0];
                    let no2 = no[1];
                    if (no1.includes(".")) {
                        no1 = no1.split(".");
                        if (no1.length > 1) {
                            afterDecimal = no1[1].length;
                            no1 = no1[0].concat(no1[1]);
                        }
                    }
                    if (no2.startsWith("+")) {
                        let val = +no2.substring(1, no2.length);
                        let z = "";
                        if (afterDecimal) {
                            val = val - afterDecimal;
                        }
                        for (let i = 0; i < val; i++) {
                            z = z.concat("0");
                        }
                        no2 = z;
                        no = no1.concat(no2);
                        // console.log('no concat',no)
                        ans = no;
                    } else if (no2.startsWith("-")) {
                        let val = +no2.substring(1, no2.length);
                        // console.log('val',val)
                        let z = "0.";
                        for (let i = 1; i < val; i++) {
                            z = z.concat("0");
                        }
                        no2 = z;
                        no = no2.concat(no1);
                        // console.log('no concat',no)
                        ans = no;
                    }
                }
            } else {
                ans = no;
            }
            original = +original;
            // console.log('ans',ans,typeof(ans))
            // console.log('original',original,typeof(original))
            // console.log('original',original,typeof(original))
            // console.log(original==ans)
            if (original == ans) {
                return ans;
            }
            return original;
        } catch (error) {
            console.log("error @ changeToString", error);
            return original;
        }
    },
};
module.exports = utilityFn;
