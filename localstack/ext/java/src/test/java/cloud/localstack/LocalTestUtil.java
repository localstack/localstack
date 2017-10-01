package cloud.localstack;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.commons.io.IOUtils;

import com.amazonaws.services.kinesis.model.Record;
import com.amazonaws.services.lambda.model.FunctionCode;

/**
 * Utility methods used for the LocalStack unit and integration tests.
 *
 * @author Waldemar Hummer
 */
public class LocalTestUtil {

	public static FunctionCode createFunctionCode(Class<?> clazz) throws Exception {
		FunctionCode code = new FunctionCode();
		ByteArrayOutputStream zipOut = new ByteArrayOutputStream();
		ByteArrayOutputStream jarOut = new ByteArrayOutputStream();
		// create zip file
		ZipOutputStream zipStream = new ZipOutputStream(zipOut);
		// create jar file
		JarOutputStream jarStream = new JarOutputStream(jarOut);

		// write class files into jar stream
		addClassToJar(clazz, jarStream);
		addClassToJar(Record.class, jarStream);
		jarStream.close();
		// write jar into zip stream
		ZipEntry zipEntry = new ZipEntry("LambdaCode.jar");
		zipStream.putNextEntry(zipEntry);
		zipStream.write(jarOut.toByteArray());
		zipStream.closeEntry();

		zipStream.close();
		code.setZipFile(ByteBuffer.wrap(zipOut.toByteArray()));

		// TODO tmp
		FileOutputStream fos = new FileOutputStream("/tmp/test.zip");
		fos.write(zipOut.toByteArray());
		fos.close();

		return code;
	}

	private static void addClassToJar(Class<?> clazz, JarOutputStream jarStream) throws IOException {
		String resource = clazz.getName().replace(".", File.separator) + ".class";
		JarEntry jarEntry = new JarEntry(resource);
		jarStream.putNextEntry(jarEntry);
		IOUtils.copy(LocalTestUtil.class.getResourceAsStream("/" + resource), jarStream);
		jarStream.closeEntry();
	}

}
