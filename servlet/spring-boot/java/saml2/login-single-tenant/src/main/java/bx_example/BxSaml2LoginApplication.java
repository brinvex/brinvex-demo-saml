/*
 * Copyright 2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package bx_example;

import example.IndexController;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

import java.util.Map;

@SpringBootApplication
        (scanBasePackageClasses = BxSaml2LoginApplication.class)
public class BxSaml2LoginApplication {

    public static void main(String[] args) {
        new SpringApplicationBuilder()
                .properties(Map.of(
                        "spring.config.location", "classpath:/application.yml",
                        "spring.config.additional-location", "file:/c:/prj/bx-demo/brinvex-demo-saml/bx-demo-saml-application.yml"
                ))
                .sources(BxSaml2LoginApplication.class, IndexController.class)
                .run(args);
    }

}
