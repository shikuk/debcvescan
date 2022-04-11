package cmd

import (
	"io"
	"net/http"
	"os"
    "archive/zip"
    "bytes"
    "io/ioutil"
    "log"
	"strconv"
	"encoding/json"

	"github.com/spf13/cobra"
)

// initializes arguments for pkg commmand
func init() {
	rootCmd.AddCommand(downloadCmd)

}

type cveSeverites map[string]string

// We want this
// type cveSeverity struct {
// 	Severity string
// }

// Nvd is a struct of NVD JSON
// https://scap.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema
// Structs from https://github.com/vulsio/go-cve-dictionary/blob/master/fetcher/nvd/nvd.go
type Nvd struct {
	CveItems            []CveItem `json:"CVE_Items"`
}

// CveItem is a struct of Nvd>CveItems
type CveItem struct {
	Cve struct {
		CveDataMeta struct {
			ID       string `json:"ID"`
		} `json:"CVE_data_meta"`
		Description struct {
			DescriptionData []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description_data"`
		} `json:"description"`
	} `json:"cve"`
	Impact struct {
		BaseMetricV2 struct {
			Severity                string  `json:"severity"`
		} `json:"baseMetricV2"`
	} `json:"impact"`
}

func readZipFile(zf *zip.File) ([]byte, error) {
    f, err := zf.Open()
    if err != nil {
        return nil, err
    }
    defer f.Close()
    return ioutil.ReadAll(f)
}

// download command
var downloadCmd = &cobra.Command{
	Use:   "download",
	Short: "Download json",
	Long:  `Download cve json file.`,
	Args:  cobra.ExactArgs(0),
	Run: func(cmd *cobra.Command, args []string) {
		// var data jsonData
		outSeverites := make(map[string]string)

		client := &http.Client{}
		req, err := http.NewRequest("GET", "https://security-tracker.debian.org/tracker/data/json", nil)
		if err != nil {
			panic(err)
		}

		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}

		defer resp.Body.Close()

		debcvejson, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}

		err = os.WriteFile("./debcvelist.json", debcvejson, 0600)
		if err != nil {
			panic(err)
		}

        // Get NVD lists because they have severity marks
		for year:= 2022; year < 2023; year++ {
			var nvdData Nvd

			resp, err := http.Get("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-" + strconv.Itoa(year) + ".json.zip")
			if err != nil {
				log.Fatal(err)
			}
			defer resp.Body.Close()
		
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Fatal(err)
			}
		
			zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
			if err != nil {
				log.Fatal(err)
			}
		
			// Read all the files from zip archive
			for _, zipFile := range zipReader.File {
				unzippedFileBytes, err := readZipFile(zipFile)
				if err != nil {
					log.Println(err)
					continue
				} else {
					log.Println("Succesfully readed file from zip:", zipFile.Name)
				}

				err2 := json.Unmarshal(unzippedFileBytes, &nvdData)
				if err2 != nil {
					panic(err)
				}

				for _, item := range nvdData.CveItems {
     				outSeverites[item.Cve.CveDataMeta.ID] = item.Impact.BaseMetricV2.Severity
				}

				// Just to check
				err = os.WriteFile("nvdcve-1.1-" + strconv.Itoa(year) + ".json", unzippedFileBytes, 0600)
				if err != nil {
					panic(err)
				}				
			}
		}

		file, _ := json.MarshalIndent(outSeverites, "", " ")

		err = os.WriteFile("./debcveseverity.json", file, 0600)
		if err != nil {
			panic(err)
		}

	},
}
