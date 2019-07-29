/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package software.amazon.kinesis.multilang.config;

import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import org.apache.commons.beanutils.ConvertUtilsBean;
import org.apache.commons.lang3.ClassUtils;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;

class DynaBeanBuilderSupport {

    private static final String BUILD_METHOD_NAME = "build";
    private static final String BUILDER_METHOD_NAME = "builder";

    private final Class<?> destinedClass;
    private final ConvertUtilsBean convertUtilsBean;
    private final List<String> classPrefixSearchList;
    private final Class<?> builderClass;

    private final Multimap<String, TypeTag> properties = HashMultimap.create();
    private final Map<String, Object> values = new HashMap<>();

    DynaBeanBuilderSupport(Class<?> destinedClass, ConvertUtilsBean convertUtilsBean,
                           List<String> classPrefixSearchList) {
        this.destinedClass = destinedClass;
        this.convertUtilsBean = convertUtilsBean;
        this.classPrefixSearchList = classPrefixSearchList;
        this.builderClass = builderClassFrom(destinedClass);

        buildProperties();
    }

    private static Class<?> builderClassFrom(Class<?> destinedClass) {
        Method builderMethod;
        try {
            builderMethod = destinedClass.getMethod(BUILDER_METHOD_NAME);
        } catch (NoSuchMethodException e) {
            return null;
        }

        return builderMethod.getReturnType();
    }

    private void buildProperties() {
        if (builderClass == null) {
            return;
        }
        try {
            builderClass.getMethod(BUILD_METHOD_NAME);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        }

        for (Method method : builderClass.getMethods()) {
            if (method.getParameterCount() == 1 && ClassUtils.isAssignable(builderClass, method.getReturnType())) {
                Class<?> paramType = method.getParameterTypes()[0];
                if (Supplier.class.isAssignableFrom(paramType) || Consumer.class.isAssignableFrom(paramType)) {
                    continue;
                }
                if (paramType.isEnum()) {
                    properties.put(method.getName(), new TypeTag(paramType, true, method));
                } else if (convertUtilsBean.lookup(paramType) == null) {
                    properties.put(method.getName(), new TypeTag(paramType, false, method));
                } else {
                    properties.put(method.getName(), new TypeTag(paramType, true, method));
                }
            }
        }
    }

    boolean isValid() {
        return builderClass != null;
    }

    private Object createForProperty(String name) {
        Optional<TypeTag> type = properties.get(name).stream().findFirst();
        return type.map(t -> {
            if (DynaBeanBuilderUtils.isBuilderOrCreate(t.type) || !t.hasConverter) {
                return new BuilderDynaBean(t.type, convertUtilsBean, null, classPrefixSearchList);
            }
            return null;
        }).orElse(null);
    }

    boolean hasValue(String name) {
        return values.containsKey(name);
    }

    Object get(String name) {
        if (values.containsKey(name)) {
            return values.get(name);
        }
        Object value = createForProperty(name);
        if (value != null) {
            values.put(name, value);
        }
        return values.get(name);
    }

    private Object[] retrieveAndResizeArray(String name, int index) {
        Object existing = values.get(name);
        Object[] destination;
        if (existing != null) {
            if (!existing.getClass().isArray()) {
                throw new IllegalStateException("Requested get for an array, but existing value isn't an array");
            }
            destination = (Object[]) existing;
            if (index >= destination.length) {
                destination = Arrays.copyOf(destination, index + 1);
                values.put(name, destination);
            }

        } else {
            destination = new Object[index + 1];
            values.put(name, destination);
        }

        return destination;
    }

    Object get(String name, int index) {
        Object[] destination = retrieveAndResizeArray(name, index);

        if (destination[index] == null) {
            destination[index] = createForProperty(name);
        }
        return destination[index];
    }

    void set(String name, Object value) {
        if (value instanceof String && properties.get(name).stream().anyMatch(t -> t.type.isEnum())) {
            TypeTag typeTag = properties.get(name).stream().filter(t -> t.type.isEnum()).findFirst().orElseThrow(
                    () -> new IllegalStateException("Expected enum type for " + name + ", but couldn't find it."));
            Class<? extends Enum> enumClass = (Class<? extends Enum>) typeTag.type;
            values.put(name, Enum.valueOf(enumClass, value.toString()));
        } else {
            values.put(name, value);
        }
    }

    void set(String name, int index, Object value) {
        Object[] destination = retrieveAndResizeArray(name, index);
        destination[index] = value;
    }

    private Object getArgument(Map.Entry<String, Object> setValue) {
        Object argument = setValue.getValue();
        if (argument instanceof Object[]) {
            TypeTag arrayType = properties.get(setValue.getKey()).stream().filter(t -> t.type.isArray()).findFirst()
                    .orElseThrow(() -> new IllegalStateException(String
                            .format("Received Object[] for %s but can't find corresponding type", setValue.getKey())));
            Object[] arrayValues = (Object[]) argument;
            Object[] destination = (Object[]) Array.newInstance(arrayType.type.getComponentType(), arrayValues.length);

            for (int i = 0; i < arrayValues.length; ++i) {
                if (arrayValues[i] instanceof BuilderDynaBean) {
                    destination[i] = ((BuilderDynaBean) arrayValues[i]).build(Object.class);
                } else {
                    destination[i] = arrayValues[i];
                }
            }

            return destination;
        }
        if (argument instanceof BuilderDynaBean) {
            argument = ((BuilderDynaBean) argument).build(Object.class);
        }
        return argument;
    }

    Object build(Function<Object, Object>... additionalMutators) {
        Method builderMethod;
        try {
            builderMethod = destinedClass.getMethod(BUILDER_METHOD_NAME);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
        Object source;
        try {
            source = builderMethod.invoke(null);
        } catch (IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
        for (Map.Entry<String, Object> setValue : values.entrySet()) {
            Object argument = getArgument(setValue);
            System.out.println("properties " + setValue + " - " + argument);
            Method mutator = properties.get(setValue.getKey()).stream()
                    .filter(t -> {
                        return ClassUtils.isAssignable(argument.getClass(), t.type);
                    }).findFirst()
                    .map(a -> a.builderMethod).orElseThrow(
                            () -> new IllegalStateException(String.format("Unable to find mutator for %s of type %s",
                                    setValue.getKey(), argument.getClass().getName())));
            try {
                source = mutator.invoke(source, argument);
            } catch (IllegalAccessException | InvocationTargetException e) {
                throw new RuntimeException(e);
            }
        }

        if (additionalMutators != null) {
            for (Function<Object, Object> mutator : additionalMutators) {
                source = mutator.apply(source);
            }
        }

        Method buildMethod;
        try {
            buildMethod = builderClass.getMethod(BUILD_METHOD_NAME);
            return buildMethod.invoke(source);
        } catch (IllegalAccessException | NoSuchMethodException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }

    }

    Collection<String> getPropertyNames() {
        return properties.keySet();
    }

    List<TypeTag> getProperty(String name) {
        if (!properties.containsKey(name)) {
            throw new IllegalArgumentException("Unknown property: " + name);
        }
        return new ArrayList<>(properties.get(name));
    }

}